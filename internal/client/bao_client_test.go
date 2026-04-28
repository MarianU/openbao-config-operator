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

// Pins the wire shape Tenant produces today. Two complementary guards:
//
//   - Every historical key must remain present with its historical
//     value. Catches accidental removal or value-mutation of fields
//     Tenant depends on.
//   - No unexpected keys may appear. Catches silent over-emission —
//     a future K8sRoleSpec field accidentally promoted to emit-by-
//     default would otherwise enter Tenant's wire body without
//     Tenant's knowledge, potentially overriding bao's mount default
//     for that field on every tenant write.
//
// TestUpsertK8sRole_OmitsUnsetOptionalFields covers the same class of
// over-emission failure but only for the optional-field names listed
// there; this test is the catch-all that spots over-emission in
// fields not yet listed (i.e. fields added to K8sRoleSpec after the
// absence-list test was last updated).
//
// If a Tenant change INTENTIONALLY adopts a new K8sRoleSpec field,
// add the new key to `want` below — the second loop's failure
// message points to this comment.
func TestUpsertK8sRole_TenantWireBody_HistoricalShapeIntact(t *testing.T) {
	t.Parallel()
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.WriteHeader(http.StatusNoContent)
	})
	renewable := true
	// Mirror tenant_controller.go's K8sRoleSpec construction verbatim.
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
			"Tenant's request body must still contain %q", key)
		require.Equal(t, expected, gotBody[key],
			"Tenant's value for %q must not change", key)
	}

	// Reverse direction: no key may appear that isn't in `want`.
	// Catches silent over-emission from new K8sRoleSpec fields that
	// don't follow the omit-when-empty convention. Failure means
	// either: (a) Tenant has intentionally adopted a new field — add
	// the key to `want` above; or (b) UpsertK8sRole is leaking a
	// field's zero value — fix the emit predicate in bao_client.go.
	for key := range gotBody {
		require.Contains(t, want, key,
			"unexpected key %q in Tenant's bao request body — "+
				"if Tenant intentionally adopted this field add it to `want`; "+
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
