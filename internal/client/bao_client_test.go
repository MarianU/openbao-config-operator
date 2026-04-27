package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	vault "github.com/hashicorp/vault/api"
)

// Spins up a local httptest server speaking just enough of the OpenBao
// HTTP API for these contract tests. Each handler returns a status + body;
// the tests assert the wrapper's behavior at our public Client interface.
func newTestClient(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err)
	return c
}

// ---- wrapStatus contract ----

func TestWrapStatus_TranslatesVaultResponseError(t *testing.T) {
	t.Parallel()
	in := &vault.ResponseError{
		StatusCode: http.StatusForbidden,
		Errors:     []string{"permission denied"},
	}
	out := wrapStatus(in)
	var se *StatusError
	require.True(t, errors.As(out, &se), "wrapStatus should produce a *StatusError")
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

func TestWrapStatus_PassesThroughNonStatusErrors(t *testing.T) {
	t.Parallel()
	in := errors.New("dial tcp: connection refused")
	out := wrapStatus(in)
	var se *StatusError
	require.False(t, errors.As(out, &se), "network errors should not be wrapped as StatusError")
	require.Equal(t, in, out, "non-status errors should pass through unchanged")
}

func TestWrapStatus_NilIsNil(t *testing.T) {
	t.Parallel()
	require.Nil(t, wrapStatus(nil))
}

// ---- DeletePolicy: idempotent on 404 ----

func TestDeletePolicy_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/sys/policies/acl/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeletePolicy(context.Background(), "missing"),
		"404 must be treated as success (idempotent delete)")
}

func TestDeletePolicy_PropagatesNon404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.DeletePolicy(context.Background(), "blocked")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se), "403 should surface as *StatusError")
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// ---- GetPolicy: contract is ("", ErrNotFound) on missing ----

func TestGetPolicy_MissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	body, err := c.GetPolicy(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound, "missing policy must surface as ErrNotFound for uniform classification")
	require.Empty(t, body)
}

func TestGetPolicy_ReturnsBodyOnHit(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"name": "editor",
				"rules": "path \"secret/*\" { capabilities = [\"read\"] }",
				"policy": "path \"secret/*\" { capabilities = [\"read\"] }"
			}
		}`))
	})
	body, err := c.GetPolicy(context.Background(), "editor")
	require.NoError(t, err)
	require.Contains(t, body, `path "secret/*"`)
}

// ---- EnableAuthMount: idempotent "already in use" ----

// EnableAuthMount idempotency depends on string-matching the server-side
// 400 message — there's no distinct status code. The exact message text
// is the contract; if the server ever changes it, every re-enable in
// production will surface as a real error and operators will see flapping
// AuthConfigured=False conditions. These cases pin the verified-good
// message variants so a wrapper-side regex regression is caught here, and
// a server-side message change forces an explicit code update rather
// than a silent break in production.
//
// Verified server messages (HashiCorp Vault 1.15+ / OpenBao 2.x):
//
//	"path is already in use at <mount>/"
//	"path is already in use"      (older paths / sys/auth shape)
//	"ALREADY IN USE"               (some upper-cased error wrappings)
func TestEnableAuthMount_SwallowsAlreadyInUse(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"errors":["path is already in use at kubernetes/"]}`,
		`{"errors":["path is already in use"]}`,
		`{"errors":["ALREADY IN USE at /sys/auth"]}`,
	}
	for _, body := range cases {
		body := body
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, body, http.StatusBadRequest)
			})
			require.NoError(t, c.EnableAuthMount(context.Background(), "kubernetes", "kubernetes"),
				"already-in-use 400 must be treated as success regardless of message capitalization")
		})
	}
}

// Belt-and-suspenders for the case nobody wants to hit: a 400 whose body
// looks similar but is NOT the idempotency signal must still surface as
// an error. A future change to isAlreadyInUse that broadens the match
// (e.g. drops the substring anchor) would fail this case.
func TestEnableAuthMount_DistinctBadRequestStillErrors(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["mount type 'kubernetes' is not supported"]}`, http.StatusBadRequest)
	})
	err := c.EnableAuthMount(context.Background(), "kubernetes", "kubernetes")
	require.Error(t, err, "unrelated 400 must NOT be classified as already-in-use")
}

func TestEnableAuthMount_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be called for empty-arg validation")
	})
	require.Error(t, c.EnableAuthMount(context.Background(), "", "kubernetes"))
	require.Error(t, c.EnableAuthMount(context.Background(), "kubernetes", ""))
}

// ---- isAlreadyInUse helper ----

func TestIsAlreadyInUse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("path is already in use at kubernetes/"), true},
		{errors.New("ALREADY IN USE at /sys/auth"), true},
		{errors.New("permission denied"), false},
		{errors.New("not found"), false},
		{errors.New(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			if got := isAlreadyInUse(tc.err); got != tc.want {
				t.Errorf("isAlreadyInUse(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Tiny sanity check that the helpers used by GetK8sRole degrade gracefully
// rather than panicking on malformed bao responses.
func TestAsHelpers_HandleNilAndOddTypes(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", asString(nil))
	require.Equal(t, "hello", asString("hello"))
	require.Equal(t, "42", asString(42))

	require.Nil(t, asStringSlice(nil))
	require.Equal(t, []string{"a", "b"}, asStringSlice([]any{"a", "b"}))
	require.Equal(t, []string{"a"}, asStringSlice([]string{"a"}))

	require.Nil(t, asBoolPtr(nil))
	tt := true
	require.Equal(t, &tt, asBoolPtr(true))
}

// Sanity guard that NewHTTPClient produces something usable for a valid
// address, and that the trailing slash is trimmed.
func TestNewHTTPClient_AcceptsValidAddrAndTrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	c, err := NewHTTPClient("http://127.0.0.1:8200/", "x")
	require.NoError(t, err)
	sc, ok := c.(*sdkClient)
	require.True(t, ok, "expected sdkClient backing")
	require.Equal(t, "http://127.0.0.1:8200", sc.underlying().Address(),
		"trailing slash should be trimmed")
}

// Construction must fail fast on an empty or whitespace-only address so
// misconfiguration surfaces at the operator process, not as repeated
// reconcile-time failures.
func TestNewHTTPClient_RejectsEmptyAddr(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"", "  ", "\t"} {
		c, err := NewHTTPClient(addr, "tok")
		require.Error(t, err, "addr=%q should fail at construction", addr)
		require.Nil(t, c)
	}
}

// ---- UpsertPolicy: URL + body shape ----

func TestUpsertPolicy_PutsPolicyAtACLPath(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	rules := `path "secret/*" { capabilities = ["read"] }`
	require.NoError(t, c.UpsertPolicy(context.Background(), "editor", rules))
	require.Equal(t, http.MethodPut, gotMethod)
	require.Equal(t, "/v1/sys/policies/acl/editor", gotPath)
	require.Equal(t, rules, gotBody["policy"])
}

func TestUpsertPolicy_PropagatesErrors(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.UpsertPolicy(context.Background(), "editor", "rules")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// ---- UpsertK8sRole: URL + body shape ----

func TestUpsertK8sRole_WritesAtAuthRolePath(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	tt := true
	spec := K8sRoleSpec{
		Policies:                      []string{"editor"},
		BoundServiceAccountNames:      []string{"default"},
		BoundServiceAccountNamespaces: []string{"team-a"},
		TokenTTL:                      "1h",
		TokenMaxTTL:                   "24h",
		Renewable:                     &tt,
	}
	require.NoError(t, c.UpsertK8sRole(context.Background(), "kubernetes", "team-a", spec))
	require.Equal(t, http.MethodPut, gotMethod)
	require.Equal(t, "/v1/auth/kubernetes/role/team-a", gotPath)
	require.Equal(t, []any{"editor"}, gotBody["token_policies"])
	require.Equal(t, []any{"default"}, gotBody["bound_service_account_names"])
	require.Equal(t, []any{"team-a"}, gotBody["bound_service_account_namespaces"])
	require.Equal(t, "1h", gotBody["token_ttl"])
	require.Equal(t, "24h", gotBody["token_max_ttl"])
	require.Equal(t, true, gotBody["token_renewable"])
}

// Optional TTL/Renewable fields must be omitted from the body when unset, so
// bao keeps its server-side defaults instead of being overwritten with zero.
func TestUpsertK8sRole_OmitsUnsetOptionalFields(t *testing.T) {
	t.Parallel()
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.UpsertK8sRole(context.Background(), "kubernetes", "minimal",
		K8sRoleSpec{Policies: []string{"viewer"}}))
	_, hasTTL := gotBody["token_ttl"]
	_, hasMaxTTL := gotBody["token_max_ttl"]
	_, hasRenewable := gotBody["token_renewable"]
	require.False(t, hasTTL, "token_ttl must be omitted when unset")
	require.False(t, hasMaxTTL, "token_max_ttl must be omitted when unset")
	require.False(t, hasRenewable, "token_renewable must be omitted when unset")
}
