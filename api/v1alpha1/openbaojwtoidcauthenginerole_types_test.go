package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

const jwtRoleName = "tenant"

func newJWTRole() *OpenBaoJWTOIDCAuthEngineRole {
	r := &OpenBaoJWTOIDCAuthEngineRole{}
	r.Namespace = sampleAliasNS
	r.Name = jwtRoleName
	r.Spec.Path = "oidc"
	r.Spec.RoleType = JWTOIDCRoleTypeOIDC
	r.Spec.UserClaim = "email"
	r.Spec.AllowedRedirectURIs = []string{"https://bao.example.com/ui/vault/auth/oidc/oidc/callback"}
	r.Spec.TokenPolicies = []string{"tenant"}
	return r
}

func TestOpenBaoJWTOIDCAuthEngineRole_GetPath(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	require.Equal(t, "auth/oidc/role/tenant", r.GetPath())
}

func TestOpenBaoJWTOIDCAuthEngineRole_IsValid(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	ok, err := r.IsValid()
	require.True(t, ok)
	require.NoError(t, err)

	r2 := newJWTRole()
	r2.Spec.RoleType = "weird"
	ok, err = r2.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "valid")

	r3 := newJWTRole()
	r3.Spec.UserClaim = ""
	ok, err = r3.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "userClaim")

	// type=oidc requires allowed_redirect_uris.
	r4 := newJWTRole()
	r4.Spec.AllowedRedirectURIs = nil
	ok, err = r4.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "allowedRedirectUris")

	// type=jwt does not.
	r5 := newJWTRole()
	r5.Spec.RoleType = JWTOIDCRoleTypeJWT
	r5.Spec.AllowedRedirectURIs = nil
	ok, err = r5.IsValid()
	require.True(t, ok)
	require.NoError(t, err)

	// BoundClaims with an empty value list is a silent lockout — every
	// login is rejected because no claim value can satisfy the empty
	// filter. Reject at admission so the operator can fix the spec
	// before traffic notices the outage.
	r6 := newJWTRole()
	r6.Spec.BoundClaims = map[string][]string{"groups": {}}
	ok, err = r6.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "boundClaims")
	require.ErrorContains(t, err, "empty")

	// An empty claim-name key is meaningless — bao stores it but no JWT
	// can carry a claim named "". Reject at admission.
	r7 := newJWTRole()
	r7.Spec.BoundClaims = map[string][]string{"": {"x"}}
	ok, err = r7.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "boundClaims")
}

// Drift comparator: sorted slices, claim-mappings via DeepEqual.
func TestOpenBaoJWTOIDCAuthEngineRole_IsEquivalent(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	r.Spec.BoundAudiences = []string{"bao-client"}

	cur := &baoclient.JWTOIDCRoleSpec{
		RoleType:            JWTOIDCRoleTypeOIDC,
		UserClaim:           "email",
		BoundAudiences:      []string{"bao-client"},
		AllowedRedirectURIs: []string{"https://bao.example.com/ui/vault/auth/oidc/oidc/callback"},
		TokenPolicies:       []string{"tenant"},
	}
	require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	cur.UserClaim = "preferred_username"
	require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
}

func TestOpenBaoJWTOIDCAuthEngineRole_ToBaoSpec(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	r.Spec.ClaimMappings = map[string]string{"email": "email"}
	spec := r.ToBaoSpec()
	require.Equal(t, JWTOIDCRoleTypeOIDC, spec.RoleType)
	require.Equal(t, "email", spec.UserClaim)
	require.Equal(t, "email", spec.ClaimMappings["email"])
}

// Drift comparator handles BoundClaims across the shapes bao returns:
// []interface{} (encoding/json default), []string (round-trip), and
// a single string. Sort order should not matter.
func TestOpenBaoJWTOIDCAuthEngineRole_BoundClaims_DriftAndCoercion(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	r.Spec.BoundClaims = map[string][]string{
		"groups": {"tenant-a-admins", "tenant-a-editors"},
	}

	// Happy path — bao returns the same list, possibly reordered, as
	// []interface{} (the shape encoding/json produces for JSON arrays).
	cur := &baoclient.JWTOIDCRoleSpec{
		RoleType:            JWTOIDCRoleTypeOIDC,
		UserClaim:           "email",
		AllowedRedirectURIs: []string{"https://bao.example.com/ui/vault/auth/oidc/oidc/callback"},
		TokenPolicies:       []string{"tenant"},
		BoundClaims: map[string]interface{}{
			"groups": []interface{}{"tenant-a-editors", "tenant-a-admins"},
		},
	}
	require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	// A single bao-side value should still match when the CR
	// declares a one-element list.
	r.Spec.BoundClaims = map[string][]string{"sub": {"alice"}}
	cur.BoundClaims = map[string]interface{}{"sub": "alice"}
	require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	// A missing key on bao's side is drift.
	r.Spec.BoundClaims = map[string][]string{"groups": {"tenant-a-admins"}}
	cur.BoundClaims = map[string]interface{}{}
	require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	// An extra key on bao's side that the CR doesn't declare is also
	// drift — the CR is authoritative.
	cur.BoundClaims = map[string]interface{}{
		"groups": []interface{}{"tenant-a-admins"},
		"sub":    "alice",
	}
	require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	// Non-string-coercible value (e.g. {"gt": 18}) the CRD can't
	// represent counts as drift, so the controller rewrites.
	r.Spec.BoundClaims = map[string][]string{"age": {"18"}}
	cur.BoundClaims = map[string]interface{}{"age": map[string]interface{}{"gt": 18}}
	require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))

	// ToBaoSpec carries the typed map across to the bao client wire
	// format, with the value as a fresh []string slice (not shared).
	// Mutating the spec slice after ToBaoSpec must not leak into the
	// returned bao payload — an aliasing regression would corrupt the
	// wire body whenever the controller reuses the CR's slice between
	// ToBaoSpec and the actual write.
	r.Spec.BoundClaims = map[string][]string{"groups": {"tenant-a-admins"}}
	spec := r.ToBaoSpec()
	require.Len(t, spec.BoundClaims, 1)
	got, ok := spec.BoundClaims["groups"].([]string)
	require.True(t, ok, "ToBaoSpec must keep the value as a []string")
	require.Equal(t, []string{"tenant-a-admins"}, got)

	// Mutate the source after the fact; the bao-side slice must NOT
	// reflect the change. (Equivalent to: the implementation copied
	// the slice rather than re-using its backing array.)
	r.Spec.BoundClaims["groups"][0] = "tampered"
	require.Equal(t, []string{"tenant-a-admins"}, got,
		"ToBaoSpec aliasing regression: mutating the spec slice leaked into the bao payload")

	// Both-sides-empty/nil round-trip: a CR that declares no BoundClaims
	// must match a bao role that has no BoundClaims, across all the
	// shapes either side can take. Without this, a comparator regression
	// that treats "nil ≠ empty map" as drift would trigger a write storm
	// every reconcile, since the operator would rewrite the role only
	// for bao to echo back the same shape it had.
	t.Run("nil_nil", func(t *testing.T) {
		r.Spec.BoundClaims = nil
		cur.BoundClaims = nil
		require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
	})
	t.Run("nil_empty_map", func(t *testing.T) {
		r.Spec.BoundClaims = nil
		cur.BoundClaims = map[string]interface{}{}
		require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
	})
	t.Run("empty_map_nil", func(t *testing.T) {
		r.Spec.BoundClaims = map[string][]string{}
		cur.BoundClaims = nil
		require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
	})
	t.Run("empty_map_empty_map", func(t *testing.T) {
		r.Spec.BoundClaims = map[string][]string{}
		cur.BoundClaims = map[string]interface{}{}
		require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
	})
}

func TestOpenBaoJWTOIDCAuthEngineRole_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	require.NoError(t, r.PrepareInternalValues(context.Background(), r))
}
