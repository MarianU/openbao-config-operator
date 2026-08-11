package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Pins both safety directions across every kind carrying the field.
// The empty-string rows are load-bearing: data kinds must read empty
// as Retain and grant kinds as Delete WITHOUT API-server defaulting
// (fake clients, stale CRDs, pruned manifests).
func TestDeletionPolicy_IsDeletable(t *testing.T) {
	t.Parallel()

	type deletable interface{ IsDeletable() bool }

	dataKind := func(policy DeletionPolicy) []deletable {
		return []deletable{
			&OpenBaoSecretEngine{Spec: OpenBaoSecretEngineSpec{DeletionPolicy: policy}},
			&OpenBaoNamespace{Spec: OpenBaoNamespaceSpec{DeletionPolicy: policy}},
			&OpenBaoAuthMethod{Spec: OpenBaoAuthMethodSpec{DeletionPolicy: policy}},
		}
	}
	grantKind := func(policy DeletionPolicy) []deletable {
		return []deletable{
			&OpenBaoPolicy{Spec: OpenBaoPolicySpec{DeletionPolicy: policy}},
			&OpenBaoKubernetesAuthRole{Spec: OpenBaoKubernetesAuthRoleSpec{DeletionPolicy: policy}},
			&OpenBaoCertAuthEngineRole{Spec: OpenBaoCertAuthEngineRoleSpec{DeletionPolicy: policy}},
			&OpenBaoJWTOIDCAuthEngineRole{Spec: OpenBaoJWTOIDCAuthEngineRoleSpec{DeletionPolicy: policy}},
			&OpenBaoPKISecretEngineRole{Spec: OpenBaoPKISecretEngineRoleSpec{DeletionPolicy: policy}},
			&OpenBaoGroup{Spec: OpenBaoGroupSpec{DeletionPolicy: policy}},
			&OpenBaoGroupAlias{Spec: OpenBaoGroupAliasSpec{DeletionPolicy: policy}},
			&OpenBaoIdentityTokenRole{Spec: OpenBaoIdentityTokenRoleSpec{DeletionPolicy: policy}},
		}
	}

	cases := []struct {
		name   string
		kinds  []deletable
		expect bool
	}{
		{"data-bearing, empty means Retain", dataKind(""), false},
		{"data-bearing, explicit Retain", dataKind(DeletionPolicyRetain), false},
		{"data-bearing, explicit Delete", dataKind(DeletionPolicyDelete), true},
		{"grant, empty means Delete", grantKind(""), true},
		{"grant, explicit Retain", grantKind(DeletionPolicyRetain), false},
		{"grant, explicit Delete", grantKind(DeletionPolicyDelete), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, k := range tc.kinds {
				require.Equalf(t, tc.expect, k.IsDeletable(), "%T", k)
			}
		})
	}
}
