package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

const (
	sampleCertRoleName = "team-a-mtls"
	sampleCertMount    = "cert"
	samplePEMBundle    = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	caBundleSecretName = "ca-bundle"
)

func newRole() *OpenBaoCertAuthEngineRole {
	r := &OpenBaoCertAuthEngineRole{}
	r.Namespace = sampleAliasNS
	r.Name = sampleCertRoleName
	r.Spec.Path = sampleCertMount
	r.Spec.CertificateRef = &CertSecretRef{Name: caBundleSecretName, Key: "ca.crt"}
	return r
}

func TestOpenBaoCertAuthEngineRole_BaoName(t *testing.T) {
	t.Parallel()
	r := newRole()
	require.Equal(t, sampleCertRoleName, r.BaoName())

	r.Spec.Name = "Override"
	require.Equal(t, "override", r.BaoName())
}

func TestOpenBaoCertAuthEngineRole_GetPath(t *testing.T) {
	t.Parallel()
	r := newRole()
	require.Equal(t, "auth/cert/certs/team-a-mtls", r.GetPath())
}

func TestOpenBaoCertAuthEngineRole_IsValid(t *testing.T) {
	t.Parallel()
	r := newRole()
	ok, err := r.IsValid()
	require.True(t, ok)
	require.NoError(t, err)

	r.Spec.CertificateRef = nil
	ok, err = r.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "certificateRef")

	r2 := newRole()
	r2.Spec.Path = ""
	ok, err = r2.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.path")
}

// PrepareInternalValues resolves the certificate from a Secret.
func TestOpenBaoCertAuthEngineRole_PrepareInternalValues_ResolvesFromSecret(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	sec := &corev1.Secret{}
	sec.Name = caBundleSecretName
	sec.Namespace = sampleAliasNS
	sec.Data = map[string][]byte{"ca.crt": []byte(samplePEMBundle)}

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()

	r := newRole()
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, r.PrepareInternalValues(ctx, r))
	require.Equal(t, samplePEMBundle, r.Status.ResolvedCertificate)
}

func TestOpenBaoCertAuthEngineRole_PrepareInternalValues_MissingSecret(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	cl := crfake.NewClientBuilder().WithScheme(scheme).Build()

	r := newRole()
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.Error(t, r.PrepareInternalValues(ctx, r))
}

func TestOpenBaoCertAuthEngineRole_PrepareInternalValues_MissingKey(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	sec := &corev1.Secret{}
	sec.Name = caBundleSecretName
	sec.Namespace = sampleAliasNS
	sec.Data = map[string][]byte{"other.crt": []byte("x")} // wrong key

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()

	r := newRole()
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	err := r.PrepareInternalValues(ctx, r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no key")
}

func TestOpenBaoCertAuthEngineRole_PrepareInternalValues_DefaultKeyName(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	sec := &corev1.Secret{}
	sec.Name = caBundleSecretName
	sec.Namespace = sampleAliasNS
	sec.Data = map[string][]byte{"ca.crt": []byte(samplePEMBundle)}

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()

	r := newRole()
	r.Spec.CertificateRef.Key = "" // default to ca.crt
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, r.PrepareInternalValues(ctx, r))
	require.Equal(t, samplePEMBundle, r.Status.ResolvedCertificate)
}

// Drift comparator: bao read with sorted slices and matching cert == equivalent.
func TestOpenBaoCertAuthEngineRole_IsEquivalent_AlignedState(t *testing.T) {
	t.Parallel()
	r := newRole()
	r.Status.ResolvedCertificate = samplePEMBundle
	r.Spec.AllowedNames = []string{"alpha", "beta"}
	r.Spec.TokenPolicies = []string{"reader"}

	cur := &baoclient.CertAuthRoleSpec{
		Certificate:   samplePEMBundle,
		AllowedNames:  []string{"beta", "alpha"}, // out of order
		TokenPolicies: []string{"reader"},
	}
	require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
}

func TestOpenBaoCertAuthEngineRole_IsEquivalent_CertDiffIsDrift(t *testing.T) {
	t.Parallel()
	r := newRole()
	r.Status.ResolvedCertificate = samplePEMBundle

	cur := &baoclient.CertAuthRoleSpec{Certificate: "different cert"}
	require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": cur}))
}

func TestOpenBaoCertAuthEngineRole_ToBaoSpec_CarriesResolvedCertificate(t *testing.T) {
	t.Parallel()
	r := newRole()
	r.Status.ResolvedCertificate = samplePEMBundle
	r.Spec.TokenPolicies = []string{"reader"}
	spec := r.ToBaoSpec()
	require.Equal(t, samplePEMBundle, spec.Certificate)
	require.Equal(t, []string{"reader"}, spec.TokenPolicies)
}
