package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// ---- EnableAuthMethod: idempotent "already in use" ----

// EnableAuthMethod idempotency depends on string-matching the server-side
// 400 message — there's no distinct status code. The exact message text
// is the contract; if the server ever changes it, every re-enable in
// production will surface as a real error and operators will see flapping
// Ready=False conditions on OpenBaoAuthMethod CRs. These cases pin the
// verified-good message variants so a wrapper-side regex regression is
// caught here, and a server-side message change forces an explicit code
// update rather than a silent break in production.
//
// Verified server messages (HashiCorp Vault 1.15+ / OpenBao 2.x):
//
//	"path is already in use at <mount>/"
//	"path is already in use"      (older paths / sys/auth shape)
//	"ALREADY IN USE"               (some upper-cased error wrappings)
func TestEnableAuthMethod_SwallowsAlreadyInUse(t *testing.T) {
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
			require.NoError(t, c.EnableAuthMethod(context.Background(), "kubernetes",
				AuthMethodMountSpec{Type: "kubernetes"}),
				"already-in-use 400 must be treated as success regardless of message capitalization")
		})
	}
}

// Belt-and-suspenders for the case nobody wants to hit: a 400 whose body
// looks similar but is NOT the idempotency signal must still surface as
// an error. A future change to isAlreadyInUse that broadens the match
// (e.g. drops the substring anchor) would fail this case.
func TestEnableAuthMethod_DistinctBadRequestStillErrors(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["mount type 'kubernetes' is not supported"]}`, http.StatusBadRequest)
	})
	err := c.EnableAuthMethod(context.Background(), "kubernetes",
		AuthMethodMountSpec{Type: "kubernetes"})
	require.Error(t, err, "unrelated 400 must NOT be classified as already-in-use")
}

func TestEnableAuthMethod_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be called for empty-arg validation")
	})
	require.Error(t, c.EnableAuthMethod(context.Background(), "",
		AuthMethodMountSpec{Type: "kubernetes"}))
	require.Error(t, c.EnableAuthMethod(context.Background(), "kubernetes",
		AuthMethodMountSpec{Type: ""}))
}

// ---- isAlreadyInUse helper ----

// TestIsAlreadyInUse pins the server-side wording variants the helper
// matches. Bao returns 400 with one of these message bodies for an
// idempotent re-enable (no distinct status code), so the wrapper has
// to peek at the message text. A server-side wording change would
// surface here before reaching production, forcing an explicit code
// update rather than a silent break.
//
// Positive variants verified against HashiCorp Vault 1.15+ and
// OpenBao 2.x:
//
//	"path is already in use at <mount>/"
//	"path is already in use"          (older sys/auth shape)
//	"ALREADY IN USE"                  (upper-cased wrapper)
//
// Negative cases guard against the match broadening: an unrelated 400
// must NOT be classified as already-in-use.
func TestIsAlreadyInUse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("path is already in use at kubernetes/"), true},
		{errors.New("path is already in use"), true},
		{errors.New("ALREADY IN USE at /sys/auth"), true},
		{errors.New("permission denied"), false},
		{errors.New("not found"), false},
		{errors.New("mount type 'kubernetes' is not supported"), false},
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

// ---- isNoDefaultIssuer helper ----

// TestIsNoDefaultIssuer pins the OpenBao 2.x 400 wording for an empty
// PKI mount. Same contract-test purpose as TestIsAlreadyInUse — a
// server-side message change must surface here, not as a controller
// stuck in an "I see a CA but read returns nothing" loop in prod.
//
// Negative cases guard against the match broadening: a 400 mentioning
// "default" for an unrelated reason must NOT classify as no-default-issuer.
func TestIsNoDefaultIssuer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("no default issuer currently configured"), true},
		{errors.New("No Default Issuer present"), true},
		{errors.New("permission denied"), false},
		{errors.New("not found"), false},
		{errors.New("default ttl exceeds max"), false},
		{errors.New(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			if got := isNoDefaultIssuer(tc.err); got != tc.want {
				t.Errorf("isNoDefaultIssuer(%q) = %v, want %v", tc.err, got, tc.want)
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
	for _, k := range []string{"audience", "alias_name_source", "token_bound_cidrs",
		"token_explicit_max_ttl", "token_no_default_policy", "token_num_uses",
		"token_period", "token_type"} {
		_, has := gotBody[k]
		require.False(t, has, "%s must be omitted when unset", k)
	}
}

// Every new field added for the KubernetesAuthEngineRole CRD must round-trip
// through the request body when set. Pinning each key/value here protects
// against silent SDK renames or accidental drops in UpsertK8sRole.
func TestUpsertK8sRole_NewFieldsRoundTrip(t *testing.T) {
	t.Parallel()
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	noDefaultPolicy := true
	numUses := 5
	spec := K8sRoleSpec{
		Policies:                 []string{"editor"},
		BoundServiceAccountNames: []string{"default"},
		Audience:                 "vault",
		AliasNameSource:          "serviceaccount_name",
		TokenBoundCIDRs:          []string{"10.0.0.0/8", "192.168.0.0/16"},
		TokenExplicitMaxTTL:      "48h",
		TokenNoDefaultPolicy:     &noDefaultPolicy,
		TokenNumUses:             &numUses,
		TokenPeriod:              "1h",
		TokenType:                "service",
	}
	require.NoError(t, c.UpsertK8sRole(context.Background(), "kubernetes", "rich", spec))
	require.Equal(t, "vault", gotBody["audience"])
	require.Equal(t, "serviceaccount_name", gotBody["alias_name_source"])
	require.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, gotBody["token_bound_cidrs"])
	require.Equal(t, "48h", gotBody["token_explicit_max_ttl"])
	require.Equal(t, true, gotBody["token_no_default_policy"])
	require.Equal(t, float64(5), gotBody["token_num_uses"]) // JSON numbers decode as float64
	require.Equal(t, "1h", gotBody["token_period"])
	require.Equal(t, "service", gotBody["token_type"])
}

// Pins the wire body UpsertK8sRole produces for a minimal K8sRoleSpec
// (the required fields only, every optional field left zero). Two
// complementary guards:
//
//   - Every required-field key must be present with its expected value.
//     Catches accidental removal or value-mutation of the bao keys
//     OpenBaoKubernetesAuthRole depends on.
//   - No unexpected keys may appear. Catches silent over-emission —
//     a future K8sRoleSpec field accidentally promoted to emit-by-
//     default would otherwise enter the wire body without the
//     controller's knowledge, potentially overriding bao's mount
//     default for that field on every reconcile.
//
// TestUpsertK8sRole_OmitsUnsetOptionalFields covers the same class of
// over-emission failure but only for the optional-field names listed
// there; this test is the catch-all that spots over-emission in
// fields not yet listed (i.e. fields added to K8sRoleSpec after the
// absence-list test was last updated).
//
// If a controller change intentionally adopts a new K8sRoleSpec field,
// add the new key to `want` below — the second loop's failure message
// points to this comment.
func TestUpsertK8sRole_MinimalSpec_HistoricalShapeIntact(t *testing.T) {
	t.Parallel()
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	renewable := true
	// Minimal K8sRoleSpec — only the required fields populated. Every
	// optional field stays at its zero value to exercise the omit-when-
	// empty contract.
	spec := K8sRoleSpec{
		Policies:                      []string{"team-a-prod-editor"},
		BoundServiceAccountNames:      []string{"default"},
		BoundServiceAccountNamespaces: []string{"team-a-prod"},
		TokenTTL:                      "3600s",
		TokenMaxTTL:                   "7200s",
		Renewable:                     &renewable,
	}
	require.NoError(t, c.UpsertK8sRole(context.Background(), "kubernetes", "team-a-prod", spec))
	want := map[string]any{
		"token_policies":                   []any{"team-a-prod-editor"},
		"bound_service_account_names":      []any{"default"},
		"bound_service_account_namespaces": []any{"team-a-prod"},
		"token_ttl":                        "3600s",
		"token_max_ttl":                    "7200s",
		"token_renewable":                  true,
	}

	// Forward direction: every pinned key must remain with its value.
	for key, expected := range want {
		require.Contains(t, gotBody, key,
			"request body must still contain %q", key)
		require.Equal(t, expected, gotBody[key],
			"value for %q must not change", key)
	}

	// Reverse direction: no key may appear that isn't in `want`.
	// Catches silent over-emission from new K8sRoleSpec fields that
	// don't follow the omit-when-empty convention. Failure means
	// either: (a) a controller has intentionally adopted a new field —
	// add the key to `want` above; or (b) UpsertK8sRole is leaking a
	// field's zero value — fix the emit predicate in bao_client.go.
	for key := range gotBody {
		require.Contains(t, want, key,
			"unexpected key %q in bao request body — "+
				"if a controller intentionally adopted this field add it to `want`; "+
				"otherwise UpsertK8sRole is over-emitting and the emit "+
				"predicate needs an omit-when-empty guard", key)
	}
}

// ---- GetK8sRole: URL, method, body decoding, 404 ----

// Pins the read-side wire shape: URL, HTTP method, and the JSON keys
// the wrapper decodes back into K8sRole fields. vault/api unmarshals
// JSON arrays as []interface{} and JSON numbers as json.Number, so
// asStringSlice / asIntPtr have to coerce — without this httptest
// coverage, a regression in those helpers would only surface against
// a real bao server.
func TestGetK8sRole_ReadsFieldsAtAuthRolePath(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"token_policies": ["editor", "viewer"],
				"bound_service_account_names": ["default", "deployer"],
				"bound_service_account_namespaces": ["team-a-app", "team-a-api"],
				"token_ttl": "1h",
				"token_max_ttl": "24h",
				"token_renewable": true,
				"audience": "vault",
				"alias_name_source": "serviceaccount_name",
				"token_bound_cidrs": ["10.0.0.0/8"],
				"token_explicit_max_ttl": "48h",
				"token_no_default_policy": true,
				"token_num_uses": 5,
				"token_period": "1h",
				"token_type": "service"
			}
		}`))
	})

	role, err := c.GetK8sRole(context.Background(), "kubernetes", "team-a")
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, gotMethod)
	require.Equal(t, "/v1/auth/kubernetes/role/team-a", gotPath)

	require.Equal(t, "team-a", role.Name)
	require.Equal(t, []string{"editor", "viewer"}, role.Policies)
	require.Equal(t, []string{"default", "deployer"}, role.BoundServiceAccountNames)
	require.Equal(t, []string{"team-a-app", "team-a-api"}, role.BoundServiceAccountNamespaces)
	require.Equal(t, "1h", role.TokenTTL)
	require.Equal(t, "24h", role.TokenMaxTTL)
	require.NotNil(t, role.Renewable)
	require.True(t, *role.Renewable)
	require.Equal(t, "vault", role.Audience)
	require.Equal(t, "serviceaccount_name", role.AliasNameSource)
	require.Equal(t, []string{"10.0.0.0/8"}, role.TokenBoundCIDRs)
	require.Equal(t, "48h", role.TokenExplicitMaxTTL)
	require.NotNil(t, role.TokenNoDefaultPolicy)
	require.True(t, *role.TokenNoDefaultPolicy)
	require.NotNil(t, role.TokenNumUses)
	require.Equal(t, 5, *role.TokenNumUses)
	require.Equal(t, "1h", role.TokenPeriod)
	require.Equal(t, "service", role.TokenType)
}

func TestGetK8sRole_MissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	role, err := c.GetK8sRole(context.Background(), "kubernetes", "missing")
	require.ErrorIs(t, err, ErrNotFound,
		"missing role must surface as ErrNotFound for uniform classification at the controller boundary")
	require.Nil(t, role)
}

func TestGetK8sRole_PropagatesNon404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	role, err := c.GetK8sRole(context.Background(), "kubernetes", "blocked")
	require.Error(t, err)
	require.Nil(t, role)
	var se *StatusError
	require.True(t, errors.As(err, &se), "403 should surface as *StatusError")
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// ---- DeleteK8sRole: URL + method + idempotency ----

func TestDeleteK8sRole_RequestShape(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.DeleteK8sRole(context.Background(), "kubernetes", "team-a"))
	require.Equal(t, http.MethodDelete, gotMethod)
	require.Equal(t, "/v1/auth/kubernetes/role/team-a", gotPath)
}

func TestDeleteK8sRole_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteK8sRole(context.Background(), "kubernetes", "missing"),
		"404 must be treated as success (idempotent delete; mirrors DeletePolicy)")
}

func TestDeleteK8sRole_PropagatesNon404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.DeleteK8sRole(context.Background(), "kubernetes", "blocked")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se), "403 should surface as *StatusError")
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// ---- asIntPtr coverage (added with the new TokenNumUses field) ----

func TestAsIntPtr(t *testing.T) {
	t.Parallel()
	require.Nil(t, asIntPtr(nil))
	require.Nil(t, asIntPtr("not-a-number"))
	require.Nil(t, asIntPtr(struct{}{}))

	five := 5
	require.Equal(t, &five, asIntPtr(json.Number("5")))
	require.Equal(t, &five, asIntPtr(int(5)))
	require.Equal(t, &five, asIntPtr(int64(5)))
	require.Equal(t, &five, asIntPtr(float64(5)))
	require.Equal(t, &five, asIntPtr("5"))
}

// ---- WithNamespace contract ----
//
// These tests verify the X-Vault-Namespace header is set when (and only when)
// a non-empty namespace is passed via WithNamespace, across the three method
// categories (mounts, policies, k8s roles). The header is the wire-level
// signal OpenBao uses to scope a request to a namespace; getting it wrong is
// a tenant-isolation bug, so the contract is asserted on every category.

// captureNamespaceHandler returns an HTTP handler that records the value of
// X-Vault-Namespace on each request and writes a minimal success response.
// The captured slice is appended to in order so multi-call tests can assert
// per-call header values.
func captureNamespaceHandler(captured *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*captured = append(*captured, r.Header.Get("X-Vault-Namespace"))
		w.Header().Set("Content-Type", "application/json")
		// Different bao endpoints expect different success shapes; respond with
		// a body broad enough to satisfy whichever method the test uses.
		switch {
		case r.URL.Path == "/v1/sys/mounts" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{}}`))
		case r.URL.Path == "/v1/sys/auth" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{}}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func TestWithNamespace_SetsHeaderOnPolicyWrite(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p", "rules", WithNamespace("acme/")))
	require.Len(t, seen, 1)
	require.Equal(t, "acme/", seen[0])
}

func TestWithNamespace_AbsentByDefault(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p", "rules"))
	require.Len(t, seen, 1)
	require.Equal(t, "", seen[0], "no opts must not set X-Vault-Namespace")
}

func TestWithNamespace_EmptyStringEquivalentToAbsent(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p", "rules", WithNamespace("")))
	require.Len(t, seen, 1)
	require.Equal(t, "", seen[0],
		`WithNamespace("") must not emit a stray empty X-Vault-Namespace`)
}

func TestWithNamespace_AppliesToK8sRoleWrite(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	err := c.UpsertK8sRole(context.Background(), "kubernetes", "role-a", K8sRoleSpec{
		Policies:                 []string{"p"},
		BoundServiceAccountNames: []string{"default"},
	}, WithNamespace("acme/"))
	require.NoError(t, err)
	require.Len(t, seen, 1)
	require.Equal(t, "acme/", seen[0])
}

func TestWithNamespace_AppliesToGetPolicy(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Vault-Namespace"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"policy":"path \"x\" {}"}}`))
	})
	body, err := c.GetPolicy(context.Background(), "p", WithNamespace("globex/"))
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.Len(t, seen, 1)
	require.Equal(t, "globex/", seen[0])
}

func TestWithNamespace_AppliesToDeletePolicy(t *testing.T) {
	t.Parallel()
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	require.NoError(t, c.DeletePolicy(context.Background(), "p", WithNamespace("acme/")))
	require.Len(t, seen, 1)
	require.Equal(t, "acme/", seen[0])
}

// ---- mount lifecycle (sys/mounts/<path>) ----

func TestEnableSecretEngine_PostsExpectedRequestShape(t *testing.T) {
	t.Parallel()
	var seenMethod, seenPath, seenBody string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	})
	err := c.EnableSecretEngine(context.Background(), "secret",
		SecretEngineMountSpec{
			Type:        "kv",
			Description: "tenant kv-v2",
			Options:     map[string]string{"version": "2"},
		})
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, seenMethod)
	require.Equal(t, "/v1/sys/mounts/secret", seenPath)
	require.Contains(t, seenBody, `"type":"kv"`)
	require.Contains(t, seenBody, `"description":"tenant kv-v2"`)
	require.Contains(t, seenBody, `"version":"2"`)
}

func TestEnableSecretEngine_AlreadyInUseTreatedAsSuccess(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["path is already in use at secret/"]}`, http.StatusBadRequest)
	})
	err := c.EnableSecretEngine(context.Background(), "secret",
		SecretEngineMountSpec{Type: "kv", Options: map[string]string{"version": "2"}})
	require.NoError(t, err, `idempotent enable: 400 "already in use" must be treated as success`)
}

func TestEnableSecretEngine_PropagatesOtherErrors(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.EnableSecretEngine(context.Background(), "secret",
		SecretEngineMountSpec{Type: "kv"})
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

func TestEnableSecretEngine_RejectsEmptyMount(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	require.Error(t, c.EnableSecretEngine(context.Background(), "",
		SecretEngineMountSpec{Type: "kv"}), "empty mount must be rejected before any request")
}

func TestEnableSecretEngine_RejectsEmptyType(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	require.Error(t, c.EnableSecretEngine(context.Background(), "secret",
		SecretEngineMountSpec{Type: ""}), "empty type must be rejected before any request")
}

func TestGetSecretEngineMount_ReturnsTypeAndOptionsOnHit(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/sys/mounts", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"secret/": {
					"type": "kv",
					"description": "tenant kv-v2",
					"options": {"version": "2"}
				}
			}
		}`))
	})
	got, err := c.GetSecretEngineMount(context.Background(), "secret")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "kv", got.Type)
	require.Equal(t, "tenant kv-v2", got.Description)
	require.Equal(t, "2", got.Options["version"])
}

func TestGetSecretEngineMount_MissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	_, err := c.GetSecretEngineMount(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound,
		"absent mount must surface as ErrNotFound for uniform classification")
}

func TestDisableSecretEngineMount_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/sys/mounts/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DisableSecretEngineMount(context.Background(), "missing"))
}

func TestDisableSecretEngineMount_PropagatesNon404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.DisableSecretEngineMount(context.Background(), "blocked")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// ---- auth-mount delete (sys/auth/<path>) ----

func TestDisableAuthMount_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/sys/auth/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DisableAuthMount(context.Background(), "missing"))
}

// ---- bao-namespace lifecycle (sys/namespaces/<name>) ----

func TestCreateNamespace_PostsExpectedPath(t *testing.T) {
	t.Parallel()
	var seenMethod, seenPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.CreateNamespace(context.Background(), "acme"))
	require.Equal(t, http.MethodPut, seenMethod, "vault/api Logical().Write uses PUT")
	require.Equal(t, "/v1/sys/namespaces/acme", seenPath)
}

func TestCreateNamespace_StripsLeadingTrailingSlashes(t *testing.T) {
	t.Parallel()
	var seenPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.CreateNamespace(context.Background(), "/acme/"))
	require.Equal(t, "/v1/sys/namespaces/acme", seenPath)
}

func TestCreateNamespace_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	require.Error(t, c.CreateNamespace(context.Background(), ""))
}

func TestCreateNamespace_PropagatesErrors(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})
	err := c.CreateNamespace(context.Background(), "acme")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

func TestGetNamespace_ReturnsPathAndIDOnHit(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/sys/namespaces/acme", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"path": "acme/",
				"id": "rGTk2"
			}
		}`))
	})
	got, err := c.GetNamespace(context.Background(), "acme")
	require.NoError(t, err)
	require.Equal(t, "acme/", got.Path)
	require.Equal(t, "rGTk2", got.ID)
}

func TestGetNamespace_MissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.GetNamespace(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound,
		"absent namespace must surface as ErrNotFound for uniform classification")
}

func TestDeleteNamespace_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/sys/namespaces/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteNamespace(context.Background(), "missing"))
}

// Bao rejects DELETE on a namespace that contains live mounts/auth/policies
// with a 400 + descriptive message. The wrapper must propagate this as a
// *StatusError so the controller can keep its finalizer in place — the
// "graceful block" behaviour from the operator-runtime concerns matrix.
func TestDeleteNamespace_PropagatesNon404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["namespace contains nested namespaces"]}`, http.StatusBadRequest)
	})
	err := c.DeleteNamespace(context.Background(), "acme")
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusBadRequest, se.StatusCode)
	require.Contains(t, err.Error(), "nested namespaces")
}

// X-Vault-Namespace plumbing for nested-namespace creation: creating
// "acme/sub" goes via POST sys/namespaces/sub with X-Vault-Namespace=acme/.
func TestNamespaceMethods_HonorWithNamespace(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		call func(c Client) error
	}{
		{"CreateNamespace", func(c Client) error {
			return c.CreateNamespace(context.Background(), "sub", WithNamespace("acme/"))
		}},
		{"GetNamespace", func(c Client) error {
			_, err := c.GetNamespace(context.Background(), "sub", WithNamespace("acme/"))
			return err
		}},
		{"DeleteNamespace", func(c Client) error {
			return c.DeleteNamespace(context.Background(), "sub", WithNamespace("acme/"))
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var seenNS string
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				seenNS = r.Header.Get("X-Vault-Namespace")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{}}`))
			})
			_ = tc.call(c)
			require.Equal(t, "acme/", seenNS, "X-Vault-Namespace must be plumbed to %s", tc.name)
		})
	}
}

// Asserts the X-Vault-Namespace plumbing reaches the mount methods, not
// just policies/roles. Mount endpoints (sys/mounts/<path>, sys/auth/<path>)
// are namespace-scoped on the bao side, so the wrapper must propagate
// WithNamespace into the SDK's per-request client.
func TestMountMethods_HonorWithNamespace(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		call func(c Client) error
	}{
		{"EnableSecretEngine", func(c Client) error {
			return c.EnableSecretEngine(context.Background(), "secret",
				SecretEngineMountSpec{Type: "kv"}, WithNamespace("acme/"))
		}},
		{"GetSecretEngineMount", func(c Client) error {
			_, err := c.GetSecretEngineMount(context.Background(), "secret", WithNamespace("acme/"))
			return err
		}},
		{"DisableSecretEngineMount", func(c Client) error {
			return c.DisableSecretEngineMount(context.Background(), "secret", WithNamespace("acme/"))
		}},
		{"DisableAuthMount", func(c Client) error {
			return c.DisableAuthMount(context.Background(), "kubernetes", WithNamespace("acme/"))
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var seenNS string
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				seenNS = r.Header.Get("X-Vault-Namespace")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{}}`))
			})
			_ = tc.call(c)
			require.Equal(t, "acme/", seenNS, "X-Vault-Namespace must be plumbed to %s", tc.name)
		})
	}
}

func TestNamespaceFromOpts(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", NamespaceFromOpts(nil), "no opts → empty namespace")
	require.Equal(t, "", NamespaceFromOpts([]CallOption{}), "empty opts → empty namespace")
	require.Equal(t, "", NamespaceFromOpts([]CallOption{WithNamespace("")}), `WithNamespace("") → empty namespace`)
	require.Equal(t, "acme/", NamespaceFromOpts([]CallOption{WithNamespace("acme/")}))

	// Last writer wins when multiple WithNamespace are passed; documents the
	// behaviour rather than asserting it as a feature, since callers are
	// expected to pass exactly one.
	require.Equal(t, "globex/", NamespaceFromOpts([]CallOption{
		WithNamespace("acme/"),
		WithNamespace("globex/"),
	}))
}

func TestWithNamespace_DifferentNamespacesPerCallOnSameClient(t *testing.T) {
	t.Parallel()
	// Asserts the safety property that motivates returning a derived
	// vault.Client per call (via clientFor): two concurrent reconciles
	// against the same shared baoclient must not contaminate each other's
	// namespace state. If clientFor mistakenly mutated c.v, the second
	// call's header would bleed back into the first.
	var seen []string
	c := newTestClient(t, captureNamespaceHandler(&seen))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p1", "rules", WithNamespace("acme/")))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p2", "rules", WithNamespace("globex/")))
	require.NoError(t, c.UpsertPolicy(context.Background(), "p3", "rules"))
	require.Equal(t, []string{"acme/", "globex/", ""}, seen)
}

// ---- TuneSecretEngine ----

func TestTuneSecretEngine_PostsToTuneEndpointWithDescriptionAndOptions(t *testing.T) {
	t.Parallel()
	var gotPath, gotMethod string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.TuneSecretEngine(context.Background(), "secret",
		SecretEngineMountSpec{Description: "kv-v2", Options: map[string]string{"version": "2"}}))
	require.Equal(t, http.MethodPost, gotMethod)
	require.Equal(t, "/v1/sys/mounts/secret/tune", gotPath)
	require.Equal(t, "kv-v2", gotBody["description"])
	require.NotNil(t, gotBody["options"])
}

// ---- GenerateRootPKI ----

func TestGenerateRootPKI_PostsCommonName_ParsesSerial(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"serial_number": "ab:cd:ef",
				"certificate":   "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
			},
		})
	})
	resp, err := c.GenerateRootPKI(context.Background(), "pki", PKIRootGenerateInput{
		CommonName: "Test CA",
		TTL:        "8760h",
		KeyType:    "rsa",
		KeyBits:    2048,
	})
	require.NoError(t, err)
	require.Equal(t, "/v1/pki/root/generate/internal", gotPath)
	require.Equal(t, "Test CA", gotBody["common_name"])
	require.Equal(t, "8760h", gotBody["ttl"])
	require.Equal(t, "rsa", gotBody["key_type"])
	require.Equal(t, "ab:cd:ef", resp.SerialNumber)
}

func TestGenerateRootPKI_RejectsEmptyCommonName(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao when CN is empty")
	})
	_, err := c.GenerateRootPKI(context.Background(), "pki", PKIRootGenerateInput{})
	require.ErrorContains(t, err, "common_name")
}

// ---- ReadPKICA ----

func TestReadPKICA_ReturnsCert(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/cert/ca", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
				"serial_number": "ab:cd",
			},
		})
	})
	resp, err := c.ReadPKICA(context.Background(), "pki")
	require.NoError(t, err)
	require.Contains(t, resp.Certificate, "BEGIN CERTIFICATE")
	require.Equal(t, "ab:cd", resp.SerialNumber)
}

func TestReadPKICA_400NoDefaultIssuer_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["no default issuer currently configured"]}`, http.StatusBadRequest)
	})
	_, err := c.ReadPKICA(context.Background(), "pki")
	require.ErrorIs(t, err, ErrNotFound,
		"bao 2.x emits 400 + 'no default issuer' for empty mounts; "+
			"the wrapper must coalesce to ErrNotFound so the controller's create path fires")
}

func TestReadPKICA_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadPKICA(context.Background(), "pki")
	require.ErrorIs(t, err, ErrNotFound)
}

// ---- WritePKIURLs / ReadPKIURLs ----

func TestWritePKIURLs_PostsAllThreeArrays(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WritePKIURLs(context.Background(), "pki", PKIURLsInput{
		IssuingCertificates:   []string{"https://example.com/ca"},
		CRLDistributionPoints: []string{"https://example.com/crl"},
		OCSPServers:           []string{"https://example.com/ocsp"},
	}))
	require.Equal(t, "/v1/pki/config/urls", gotPath)
	require.NotNil(t, gotBody["issuing_certificates"])
	require.NotNil(t, gotBody["crl_distribution_points"])
	require.NotNil(t, gotBody["ocsp_servers"])
}

func TestReadPKIURLs_DecodesAllThreeArrays(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/config/urls", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"issuing_certificates":    []any{"https://a.example.com/ca"},
				"crl_distribution_points": []any{"https://a.example.com/crl"},
				"ocsp_servers":            []any{},
			},
		})
	})
	urls, err := c.ReadPKIURLs(context.Background(), "pki")
	require.NoError(t, err)
	require.Equal(t, []string{"https://a.example.com/ca"}, urls.IssuingCertificates)
	require.Equal(t, []string{"https://a.example.com/crl"}, urls.CRLDistributionPoints)
	require.Empty(t, urls.OCSPServers)
}

// ---- WritePKIRole / ReadPKIRole / DeletePKIRole ----

func TestWritePKIRole_PostsRoleBody(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WritePKIRole(context.Background(), "pki", "web", PKIRoleSpec{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		KeyType:         "rsa",
		KeyBits:         2048,
		TTL:             "720h",
	}))
	require.Equal(t, "/v1/pki/roles/web", gotPath)
	require.Equal(t, "rsa", gotBody["key_type"])
	require.Equal(t, true, gotBody["allow_subdomains"])
	require.Equal(t, "720h", gotBody["ttl"])
	// Zero-valued fields must NOT be sent — bao keeps its defaults.
	_, hasServerFlag := gotBody["server_flag"]
	require.False(t, hasServerFlag, "zero-valued fields elided from write body")
}

func TestReadPKIRole_DecodesAndNormalizesTTL(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/pki/roles/web", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"allowed_domains":  []any{"example.com"},
				"allow_subdomains": true,
				"server_flag":      true,
				"client_flag":      true,
				"key_type":         "rsa",
				"key_bits":         2048,
				"ttl":              2592000, // bao returns int seconds
				"max_ttl":          0,
			},
		})
	})
	role, err := c.ReadPKIRole(context.Background(), "pki", "web")
	require.NoError(t, err)
	require.Equal(t, []string{"example.com"}, role.AllowedDomains)
	require.True(t, role.AllowSubdomains)
	require.Equal(t, "2592000s", role.TTL,
		"int seconds normalized to <n>s string for spec-shape round-trip")
	require.Equal(t, "", role.MaxTTL, "ttl=0 elided (matches spec zero-value)")
}

func TestReadPKIRole_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadPKIRole(context.Background(), "pki", "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeletePKIRole_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/pki/roles/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeletePKIRole(context.Background(), "pki", "missing"),
		"404 = already gone, treated as idempotent success")
}

// ---- WriteIdentityGroup / ReadIdentityGroup / DeleteIdentityGroup ----

func TestWriteIdentityGroup_PostsAtIdentityGroupPath(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":   "g-100",
				"name": "team-a",
			},
		})
	})
	out, err := c.WriteIdentityGroup(context.Background(), IdentityGroupSpec{
		Name:     "team-a",
		Type:     "internal",
		Policies: []string{"reader"},
		Metadata: map[string]string{"owner": "platform"},
	})
	require.NoError(t, err)
	require.Equal(t, http.MethodPut, gotMethod, "vault/api Logical().Write uses PUT")
	require.Equal(t, "/v1/identity/group", gotPath)
	require.Equal(t, "team-a", gotBody["name"])
	require.Equal(t, "internal", gotBody["type"])
	require.Equal(t, []any{"reader"}, gotBody["policies"])
	require.Equal(t, "g-100", out.ID)
}

// On id-update bao returns 204 (nil resp). The wrapper must round-trip
// the spec values so the StatusMutator has them.
func TestWriteIdentityGroup_NilResponse_RoundTripsSpec(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	out, err := c.WriteIdentityGroup(context.Background(), IdentityGroupSpec{
		ID:       "g-existing",
		Name:     "team-a",
		Type:     "internal",
		Policies: []string{"editor"},
	})
	require.NoError(t, err)
	require.Equal(t, "g-existing", out.ID, "id must round-trip on no-content response")
	require.Equal(t, "team-a", out.Name)
}

func TestWriteIdentityGroup_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao for empty name")
	})
	_, err := c.WriteIdentityGroup(context.Background(), IdentityGroupSpec{})
	require.Error(t, err)
}

func TestReadIdentityGroup_DecodesGroup(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/identity/group/name/team-a", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":                "g-100",
				"name":              "team-a",
				"type":              "internal",
				"policies":          []any{"reader", "editor"},
				"member_group_ids":  []any{"g-other"},
				"member_entity_ids": []any{"e-1", "e-2"},
				"metadata":          map[string]any{"owner": "platform"},
			},
		})
	})
	g, err := c.ReadIdentityGroup(context.Background(), "team-a")
	require.NoError(t, err)
	require.Equal(t, "g-100", g.ID)
	require.Equal(t, "internal", g.Type)
	require.Equal(t, []string{"reader", "editor"}, g.Policies)
	require.Equal(t, []string{"g-other"}, g.MemberGroupIDs)
	require.Equal(t, []string{"e-1", "e-2"}, g.MemberEntityIDs)
	require.Equal(t, "platform", g.Metadata["owner"])
}

func TestReadIdentityGroup_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadIdentityGroup(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteIdentityGroup_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/identity/group/name/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteIdentityGroup(context.Background(), "missing"))
}

// ---- Identity group aliases ----

func TestWriteIdentityGroupAlias_PostsBodyShape(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":             "ga-1",
				"name":           "alice@example.com",
				"mount_accessor": "auth_oidc_abc",
				"canonical_id":   "g-100",
			},
		})
	})
	out, err := c.WriteIdentityGroupAlias(context.Background(), IdentityGroupAliasSpec{
		Name:          "alice@example.com",
		MountAccessor: "auth_oidc_abc",
		CanonicalID:   "g-100",
	})
	require.NoError(t, err)
	require.Equal(t, "/v1/identity/group-alias", gotPath)
	require.Equal(t, "alice@example.com", gotBody["name"])
	require.Equal(t, "auth_oidc_abc", gotBody["mount_accessor"])
	require.Equal(t, "g-100", gotBody["canonical_id"])
	require.Equal(t, "ga-1", out.ID)
}

func TestWriteIdentityGroupAlias_RejectsEmpties(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao with empty fields")
	})
	_, err := c.WriteIdentityGroupAlias(context.Background(), IdentityGroupAliasSpec{Name: "x"})
	require.Error(t, err)
	_, err = c.WriteIdentityGroupAlias(context.Background(), IdentityGroupAliasSpec{MountAccessor: "y"})
	require.Error(t, err)
}

func TestReadIdentityGroupAliasByID(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/identity/group-alias/id/ga-1", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":             "ga-1",
				"name":           "alice@example.com",
				"mount_accessor": "auth_oidc_abc",
				"canonical_id":   "g-100",
			},
		})
	})
	g, err := c.ReadIdentityGroupAliasByID(context.Background(), "ga-1")
	require.NoError(t, err)
	require.Equal(t, "ga-1", g.ID)
	require.Equal(t, "alice@example.com", g.Name)
	require.Equal(t, "auth_oidc_abc", g.MountAccessor)
	require.Equal(t, "g-100", g.CanonicalID)
}

func TestReadIdentityGroupAliasByID_404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadIdentityGroupAliasByID(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFindIdentityGroupAlias_UsesKeyInfo(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// vault/api LIST uses GET with ?list=true
		require.Equal(t, "/v1/identity/group-alias/id", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []any{"ga-1", "ga-2"},
				"key_info": map[string]any{
					"ga-1": map[string]any{
						"name":           "other@example.com",
						"mount_accessor": "auth_oidc_xyz",
					},
					"ga-2": map[string]any{
						"name":           "alice@example.com",
						"mount_accessor": "auth_oidc_abc",
						"canonical_id":   "g-100",
					},
				},
			},
		})
	})
	out, err := c.FindIdentityGroupAlias(context.Background(), "alice@example.com", "auth_oidc_abc")
	require.NoError(t, err)
	require.Equal(t, "ga-2", out.ID)
	require.Equal(t, "g-100", out.CanonicalID)
}

func TestFindIdentityGroupAlias_NotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys":     []any{},
				"key_info": map[string]any{},
			},
		})
	})
	_, err := c.FindIdentityGroupAlias(context.Background(), "ghost", "auth_xyz")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteIdentityGroupAliasByID_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/identity/group-alias/id/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteIdentityGroupAliasByID(context.Background(), "missing"))
}

// ---- Identity OIDC token roles ----

func TestWriteIdentityTokenRole_PostsAtIdentityOIDCRolePath(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WriteIdentityTokenRole(context.Background(), "aws-tokens",
		IdentityTokenRoleSpec{
			Key:      "platform",
			Template: `{"sub": "{{identity.entity.id}}"}`,
			ClientID: "arn:aws:iam::123:role/X",
			TTL:      "1h",
		}))
	require.Equal(t, "/v1/identity/oidc/role/aws-tokens", gotPath)
	require.Equal(t, "platform", gotBody["key"])
	require.Equal(t, "1h", gotBody["ttl"])
	require.Contains(t, gotBody["template"].(string), "identity.entity.id")
	require.Equal(t, "arn:aws:iam::123:role/X", gotBody["client_id"])
}

func TestWriteIdentityTokenRole_RejectsEmpties(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao with empty inputs")
	})
	require.Error(t, c.WriteIdentityTokenRole(context.Background(), "",
		IdentityTokenRoleSpec{Key: "k"}))
	require.Error(t, c.WriteIdentityTokenRole(context.Background(), "r",
		IdentityTokenRoleSpec{}))
}

// TTL normalisation: bao returns int seconds; the wrapper renders as
// <n>s for stable spec round-trip.
func TestReadIdentityTokenRole_TTLNormalisation(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/identity/oidc/role/aws-tokens", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"key":       "platform",
				"template":  "tmpl",
				"client_id": "cid",
				"ttl":       3600,
			},
		})
	})
	out, err := c.ReadIdentityTokenRole(context.Background(), "aws-tokens")
	require.NoError(t, err)
	require.Equal(t, "platform", out.Key)
	require.Equal(t, "3600s", out.TTL)
}

func TestReadIdentityTokenRole_404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadIdentityTokenRole(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteIdentityTokenRole_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/identity/oidc/role/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteIdentityTokenRole(context.Background(), "missing"))
}

// ---- AuthMethod (sys/auth/<path>) ----

func TestEnableAuthMethod_PostsAtSysAuthWithConfig(t *testing.T) {
	t.Parallel()
	var seenMethod, seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.EnableAuthMethod(context.Background(), "oidc",
		AuthMethodMountSpec{
			Type:        "oidc",
			Description: "tenant oidc",
			Config: AuthMethodConfig{
				DefaultLeaseTTL: "1h",
				MaxLeaseTTL:     "24h",
			},
		}))
	require.Equal(t, http.MethodPost, seenMethod)
	require.Equal(t, "/v1/sys/auth/oidc", seenPath)
	require.Equal(t, "oidc", seenBody["type"])
	require.Equal(t, "tenant oidc", seenBody["description"])
	cfg, _ := seenBody["config"].(map[string]any)
	require.Equal(t, "1h", cfg["default_lease_ttl"])
	require.Equal(t, "24h", cfg["max_lease_ttl"])
}

// Idempotency: a re-POST returning 400 "already in use" is success.
func TestEnableAuthMethod_AlreadyInUseTreatedAsSuccess(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["path is already in use at oidc/"]}`, http.StatusBadRequest)
	})
	require.NoError(t, c.EnableAuthMethod(context.Background(), "oidc",
		AuthMethodMountSpec{Type: "oidc"}))
}

func TestEnableAuthMethod_RejectsEmpties(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	require.Error(t, c.EnableAuthMethod(context.Background(), "",
		AuthMethodMountSpec{Type: "oidc"}))
	require.Error(t, c.EnableAuthMethod(context.Background(), "oidc",
		AuthMethodMountSpec{Type: ""}))
}

func TestTuneAuthMethod_PostsAtAuthTuneEndpoint(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.TuneAuthMethod(context.Background(), "oidc",
		AuthMethodMountSpec{
			Description: "updated",
			Config: AuthMethodConfig{
				DefaultLeaseTTL: "2h",
			},
		}))
	require.Equal(t, "/v1/sys/mounts/auth/oidc/tune", seenPath)
	require.Equal(t, "updated", seenBody["description"])
	require.Equal(t, "2h", seenBody["default_lease_ttl"])
}

func TestGetAuthMethod_ReturnsTypeDescriptionAccessor(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/auth", r.URL.Path)
		_, _ = w.Write([]byte(`{
			"data": {
				"oidc/": {
					"type": "oidc",
					"description": "tenant oidc",
					"accessor": "auth_oidc_abc123",
					"config": {
						"default_lease_ttl": 3600,
						"max_lease_ttl": 86400,
						"listing_visibility": "unauth"
					}
				}
			}
		}`))
	})
	out, err := c.GetAuthMethod(context.Background(), "oidc")
	require.NoError(t, err)
	require.Equal(t, "oidc", out.Type)
	require.Equal(t, "tenant oidc", out.Description)
	require.Equal(t, "auth_oidc_abc123", out.Accessor)
	require.Equal(t, "3600s", out.Config.DefaultLeaseTTL,
		"int seconds normalised to <n>s for spec round-trip")
	require.Equal(t, "86400s", out.Config.MaxLeaseTTL)
	require.Equal(t, "unauth", out.Config.ListingVisibility)
}

func TestGetAuthMethod_MissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	_, err := c.GetAuthMethod(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

// ---- Cert auth (auth/<mount>/config + auth/<mount>/certs/<name>) ----

func TestWriteCertAuthConfig_PostsAtAuthConfigPath(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	disable := false
	cache := 200
	require.NoError(t, c.WriteCertAuthConfig(context.Background(), "cert",
		CertAuthConfigSpec{
			DisableBinding: &disable,
			OCSPCacheSize:  &cache,
		}))
	require.Equal(t, "/v1/auth/cert/config", seenPath)
	require.Equal(t, false, seenBody["disable_binding"])
	require.Equal(t, float64(200), seenBody["ocsp_cache_size"])
	_, hasFailOpen := seenBody["ocsp_fail_open"]
	require.False(t, hasFailOpen, "unset fields elided from body")
}

func TestReadCertAuthConfig_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadCertAuthConfig(context.Background(), "cert")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestWriteCertAuthRole_PostsCertAndPolicies(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WriteCertAuthRole(context.Background(), "cert", "team-a",
		CertAuthRoleSpec{
			Certificate:   "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
			AllowedNames:  []string{"team-a.example.com"},
			TokenPolicies: []string{"reader"},
			TokenTTL:      "1h",
		}))
	require.Equal(t, "/v1/auth/cert/certs/team-a", seenPath)
	require.Contains(t, seenBody["certificate"], "BEGIN CERTIFICATE")
	require.Equal(t, []any{"team-a.example.com"}, seenBody["allowed_names"])
	require.Equal(t, []any{"reader"}, seenBody["token_policies"])
	require.Equal(t, "1h", seenBody["token_ttl"])
}

func TestWriteCertAuthRole_RejectsEmptyCertificate(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao with empty certificate")
	})
	require.Error(t, c.WriteCertAuthRole(context.Background(), "cert", "team-a",
		CertAuthRoleSpec{}))
}

func TestReadCertAuthRole_TTLNormalisation(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/cert/certs/team-a", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":    "PEM",
				"token_ttl":      3600,
				"token_policies": []any{"reader"},
			},
		})
	})
	out, err := c.ReadCertAuthRole(context.Background(), "cert", "team-a")
	require.NoError(t, err)
	require.Equal(t, "PEM", out.Certificate)
	require.Equal(t, "3600s", out.TokenTTL)
	require.Equal(t, []string{"reader"}, out.TokenPolicies)
}

func TestDeleteCertAuthRole_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteCertAuthRole(context.Background(), "cert", "missing"))
}

// ---- JWT/OIDC auth (auth/<mount>/config + auth/<mount>/role/<name>) ----

func TestWriteJWTOIDCConfig_OIDCFields(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WriteJWTOIDCConfig(context.Background(), "oidc",
		JWTOIDCConfigSpec{
			OIDCDiscoveryURL: "https://accounts.example.com",
			OIDCClientID:     "bao-client",
			OIDCClientSecret: "shhhh",
			DefaultRole:      "tenant",
		}))
	require.Equal(t, "/v1/auth/oidc/config", seenPath)
	require.Equal(t, "https://accounts.example.com", seenBody["oidc_discovery_url"])
	require.Equal(t, "bao-client", seenBody["oidc_client_id"])
	require.Equal(t, "shhhh", seenBody["oidc_client_secret"])
	require.Equal(t, "tenant", seenBody["default_role"])
}

func TestWriteJWTOIDCRole_PostsAtRolePath(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.WriteJWTOIDCRole(context.Background(), "oidc", "tenant",
		JWTOIDCRoleSpec{
			RoleType:            "oidc",
			UserClaim:           "email",
			BoundAudiences:      []string{"bao-client"},
			AllowedRedirectURIs: []string{"https://bao.example.com/ui/vault/auth/oidc/oidc/callback"},
			TokenPolicies:       []string{"tenant"},
		}))
	require.Equal(t, "/v1/auth/oidc/role/tenant", seenPath)
	require.Equal(t, "oidc", seenBody["role_type"])
	require.Equal(t, "email", seenBody["user_claim"])
	require.Equal(t, []any{"bao-client"}, seenBody["bound_audiences"])
}

func TestWriteJWTOIDCRole_RejectsEmptyRoleType(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao with empty role_type")
	})
	require.Error(t, c.WriteJWTOIDCRole(context.Background(), "oidc", "tenant",
		JWTOIDCRoleSpec{}))
}

func TestDeleteJWTOIDCRole_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteJWTOIDCRole(context.Background(), "oidc", "missing"))
}

// ---- Kubernetes auth (auth/<mount>/config) ----

func TestWriteK8sAuthConfig_PostsAtAuthConfigPath(t *testing.T) {
	t.Parallel()
	var seenPath string
	var seenBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusNoContent)
	})
	disableISS := true
	require.NoError(t, c.WriteK8sAuthConfig(context.Background(), "kubernetes",
		K8sAuthConfigSpec{
			KubernetesHost:       "https://kubernetes.default.svc:443",
			KubernetesCACert:     "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
			TokenReviewerJWT:     "eyJ.fake.jwt",
			Issuer:               "kubernetes/serviceaccount",
			DisableISSValidation: &disableISS,
		}))
	require.Equal(t, "/v1/auth/kubernetes/config", seenPath)
	require.Equal(t, "https://kubernetes.default.svc:443", seenBody["kubernetes_host"])
	require.Contains(t, seenBody["kubernetes_ca_cert"], "BEGIN CERTIFICATE")
	require.Equal(t, "eyJ.fake.jwt", seenBody["token_reviewer_jwt"])
	require.Equal(t, "kubernetes/serviceaccount", seenBody["issuer"])
	require.Equal(t, true, seenBody["disable_iss_validation"])
	// Unset bool pointers must NOT appear in the body — bao defaults
	// stay in effect when the spec doesn't pin them.
	_, hasLocalCA := seenBody["disable_local_ca_jwt"]
	require.False(t, hasLocalCA, "unset bool pointers elided from body")
}

func TestWriteK8sAuthConfig_RejectsEmptyHost(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not hit bao with empty kubernetes_host")
	})
	require.Error(t, c.WriteK8sAuthConfig(context.Background(), "kubernetes",
		K8sAuthConfigSpec{}))
}

func TestReadK8sAuthConfig_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadK8sAuthConfig(context.Background(), "kubernetes")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestReadK8sAuthConfig_ParsesFields(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/kubernetes/config", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"kubernetes_host":        "https://kubernetes.default.svc:443",
				"kubernetes_ca_cert":     "PEM",
				"pem_keys":               []any{"key-a", "key-b"},
				"issuer":                 "kubernetes/serviceaccount",
				"disable_iss_validation": true,
			},
		})
	})
	out, err := c.ReadK8sAuthConfig(context.Background(), "kubernetes")
	require.NoError(t, err)
	require.Equal(t, "https://kubernetes.default.svc:443", out.KubernetesHost)
	require.Equal(t, "PEM", out.KubernetesCACert)
	require.Equal(t, []string{"key-a", "key-b"}, out.PEMKeys)
	require.Equal(t, "kubernetes/serviceaccount", out.Issuer)
	require.NotNil(t, out.DisableISSValidation)
	require.True(t, *out.DisableISSValidation)
}

// ---- WriteTransitKey / UpdateTransitKeyConfig / ReadTransitKey / DeleteTransitKey ----

func TestWriteTransitKey_PostsCreateBodyAtKeyPath(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	derived := true
	conv := false
	keySize := 32
	require.NoError(t, c.WriteTransitKey(context.Background(), "transit", "app-key", TransitKeySpec{
		Type:                 "aes256-gcm96",
		Derived:              &derived,
		ConvergentEncryption: &conv,
		KeySize:              &keySize,
		AutoRotatePeriod:     "720h",
	}))
	require.Equal(t, "/v1/transit/keys/app-key", gotPath)
	require.Equal(t, "aes256-gcm96", gotBody["type"])
	require.Equal(t, true, gotBody["derived"])
	require.Equal(t, false, gotBody["convergent_encryption"])
	require.Equal(t, "720h", gotBody["auto_rotate_period"])
	// Mutable-only fields must NOT appear on the create call — the
	// controller's two-phase pattern relies on this split.
	for _, k := range []string{"min_decryption_version", "min_encryption_version", "deletion_allowed"} {
		_, present := gotBody[k]
		require.False(t, present, "create body must not include config-only field %q", k)
	}
}

func TestUpdateTransitKeyConfig_PostsConfigBodyAtConfigPath(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	delAllowed := true
	minDec := 2
	minEnc := 0
	require.NoError(t, c.UpdateTransitKeyConfig(context.Background(), "transit", "app-key", TransitKeySpec{
		MinDecryptionVersion: &minDec,
		MinEncryptionVersion: &minEnc,
		DeletionAllowed:      &delAllowed,
		AutoRotatePeriod:     "0",
	}))
	require.Equal(t, "/v1/transit/keys/app-key/config", gotPath)
	require.Equal(t, true, gotBody["deletion_allowed"])
	// json round-trip turns ints into float64 — assert via the numeric value.
	require.EqualValues(t, 2, gotBody["min_decryption_version"])
	require.EqualValues(t, 0, gotBody["min_encryption_version"])
	require.Equal(t, "0", gotBody["auto_rotate_period"])
	// Create-only fields must NOT appear on the config call.
	for _, k := range []string{"type", "derived", "convergent_encryption", "key_size"} {
		_, present := gotBody[k]
		require.False(t, present, "config body must not include create-only field %q", k)
	}
}

func TestReadTransitKey_DecodesFullShape(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/transit/keys/app-key", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"name":                   "app-key",
				"type":                   "aes256-gcm96",
				"derived":                false,
				"convergent_encryption":  false,
				"exportable":             false,
				"allow_plaintext_backup": false,
				"auto_rotate_period":     2592000, // bao returns int seconds
				"deletion_allowed":       true,
				"min_decryption_version": 1,
				"min_encryption_version": 0,
				"latest_version":         3,
				"creation_time":          "2026-05-04T00:00:00Z",
				"supports_encryption":    true,
				"supports_decryption":    true,
				"supports_signing":       false,
				"supports_derivation":    false,
				"imported_key":           false,
				"keys": map[string]any{
					"1": map[string]any{"creation_time": "2026-05-04T00:00:00Z"},
				},
			},
		})
	})
	info, err := c.ReadTransitKey(context.Background(), "transit", "app-key")
	require.NoError(t, err)
	require.Equal(t, "aes256-gcm96", info.Type)
	require.Equal(t, 2592000, info.AutoRotatePeriod, "int seconds preserved on read")
	require.Equal(t, 3, info.LatestVersion)
	require.True(t, info.DeletionAllowed)
	require.True(t, info.SupportsEncryption)
	require.NotNil(t, info.Keys, "version map round-trips opaque")
}

func TestReadTransitKey_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadTransitKey(context.Background(), "transit", "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteTransitKey_Swallows404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/transit/keys/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteTransitKey(context.Background(), "transit", "missing"),
		"404 = already gone, idempotent success")
}

func TestDeleteTransitKey_400DeletionNotAllowed(t *testing.T) {
	t.Parallel()
	// Pin bao's exact error body shape. A wording change upstream
	// surfaces here as a test failure — without this guard, bao could
	// rename the message, the substring match would fail, and the
	// wrapper would silently emit a generic *StatusError{400} that
	// classifies as ReasonBaoError instead of DeleteBlocked.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["deletion is not allowed for key app-key"]}`, http.StatusBadRequest)
	})
	err := c.DeleteTransitKey(context.Background(), "transit", "app-key")
	require.ErrorIs(t, err, ErrDeletionNotAllowed)
}

func TestDeleteTransitKey_400OtherBody_PropagatesAsStatusError(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["mount is sealed"]}`, http.StatusBadRequest)
	})
	err := c.DeleteTransitKey(context.Background(), "transit", "app-key")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrDeletionNotAllowed,
		"400 with a different body must NOT classify as DeletionNotAllowed")
	var se *StatusError
	require.True(t, errors.As(err, &se))
	require.Equal(t, http.StatusBadRequest, se.StatusCode)
}

// ---- TLS env-var driven configuration ----
//
// NewHTTPClient builds its config via vault.DefaultConfig(), which calls
// (*Config).ReadEnvironment(). That reader picks up VAULT_CACERT,
// VAULT_CAPATH, VAULT_CACERT_BYTES, VAULT_TLS_SERVER_NAME, VAULT_SKIP_VERIFY
// and friends, and applies them to the underlying http.Transport's
// TLSClientConfig before the first request leaves the process.
//
// These tests pin that contract empirically: spin up an httptest TLS
// server (which signs with its own ephemeral CA, untrusted by system
// roots), drive NewHTTPClient through each of the three modes operators
// care about, and assert the handshake outcome.
//
// Tests do not call t.Parallel() — env vars are process-global and
// t.Setenv disallows parallelism in the same test.

// tlsServer returns an httptest TLS server that answers /v1/sys/mounts
// with an empty mounts object. That's the path exercised by
// CheckKVv2Mount, which is the cheapest Client method that proves a
// real TLS handshake happened.
func tlsServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeServerCertAsCA persists the httptest server's leaf cert as a PEM
// CA bundle on disk and returns the path. The Vault SDK reads this
// bundle via VAULT_CACERT and loads it into RootCAs.
func writeServerCertAsCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	})
	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestNewHTTPClient_TLS_TrustsCABundleFromEnv(t *testing.T) {
	srv := tlsServer(t)
	caPath := writeServerCertAsCA(t, srv)

	t.Setenv("VAULT_CACERT", caPath)
	t.Setenv("VAULT_SKIP_VERIFY", "")

	c, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err)
	_, err = c.CheckKVv2Mount(context.Background(), "secret")
	require.NoError(t, err,
		"VAULT_CACERT pointing at the server's cert must make the handshake succeed")
}

func TestNewHTTPClient_TLS_SkipVerifyAcceptsUntrustedCert(t *testing.T) {
	srv := tlsServer(t)

	t.Setenv("VAULT_CACERT", "")
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	c, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err)
	_, err = c.CheckKVv2Mount(context.Background(), "secret")
	require.NoError(t, err,
		"VAULT_SKIP_VERIFY=true must bypass cert validation entirely")
}

func TestNewHTTPClient_TLS_NoBundleNoSkipVerifyRejectsUntrustedCert(t *testing.T) {
	srv := tlsServer(t)

	// Neither knob set: SDK falls back to system roots, which don't
	// trust httptest's private CA. Handshake must fail.
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")

	c, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err)
	_, err = c.CheckKVv2Mount(context.Background(), "secret")
	require.Error(t, err, "untrusted cert without skip-verify must fail at TLS handshake")
	// Be tolerant of Go-version drift in the exact wording — every variant
	// surfaces one of these tokens.
	msg := err.Error()
	require.True(t,
		strings.Contains(msg, "x509") ||
			strings.Contains(msg, "certificate") ||
			strings.Contains(msg, "tls:"),
		"expected an x509 / tls error, got: %s", msg)
}

func TestNewHTTPClient_TLS_MissingCAFileFallsBackToSystemRoots(t *testing.T) {
	srv := tlsServer(t)

	// VAULT_CACERT points at a path that doesn't exist — the operator
	// hits this when the bao-ca-bundle Secret is `optional: true` and
	// absent. The Vault SDK errors hard here without our probe; with
	// it, the env var is dropped and the SDK falls back to system roots.
	t.Setenv("VAULT_CACERT", filepath.Join(t.TempDir(), "missing-ca.crt"))
	t.Setenv("VAULT_SKIP_VERIFY", "")

	c, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err, "missing CA file must not crash the constructor")
	// Post-condition: the helper must have actually unset the env var.
	// A regression that returns early on stat error without unsetting
	// would let the SDK crash the next time DefaultConfig() reads it,
	// e.g. during a per-call client clone.
	require.Empty(t, os.Getenv("VAULT_CACERT"),
		"unsetMissingCAEnv must have cleared VAULT_CACERT after stat-on-missing-file failed")
	// System roots don't trust the httptest private CA, so the request
	// itself must still fail — at TLS handshake time, not setup time.
	_, err = c.CheckKVv2Mount(context.Background(), "secret")
	require.Error(t, err, "untrusted cert without skip-verify must fail at TLS")
}

// Mirror invariant: when the file VAULT_CACERT points at DOES exist, the
// helper must leave the env var in place. A regression to "unset
// unconditionally" would silently fall back to system roots in prod and
// silently break TLS to a private bao with a real CA bundle mounted.
func TestNewHTTPClient_TLS_PresentCAFilePreservesEnv(t *testing.T) {
	srv := tlsServer(t)
	caPath := writeServerCertAsCA(t, srv)
	t.Setenv("VAULT_CACERT", caPath)
	t.Setenv("VAULT_SKIP_VERIFY", "")

	_, err := NewHTTPClient(srv.URL, "test-token")
	require.NoError(t, err)
	require.Equal(t, caPath, os.Getenv("VAULT_CACERT"),
		"unsetMissingCAEnv must leave VAULT_CACERT untouched when the file exists")
}

// ---- silence linter on imports used only by appended tests ----
var _ = io.Discard
