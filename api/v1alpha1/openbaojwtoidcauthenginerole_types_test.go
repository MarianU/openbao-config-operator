package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
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

func TestOpenBaoJWTOIDCAuthEngineRole_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	r := newJWTRole()
	require.NoError(t, r.PrepareInternalValues(context.Background(), r))
}
