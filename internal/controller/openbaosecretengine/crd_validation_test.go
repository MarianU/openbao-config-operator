package openbaosecretengine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

// envtest uses the apiserver+etcd binaries pointed at by KUBEBUILDER_ASSETS;
// `make test` sets this. Without it, every envtest test in this file fails
// loudly (t.Fatal) rather than silently skipping.

var (
	testEnv *envtest.Environment
	testCfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		os.Exit(m.Run())
	}
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "config", "crd", "bases"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start failed: %v\n", err)
		os.Exit(1)
	}
	testCfg = cfg

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "envtest stop failed: %v\n", err)
	}
	os.Exit(code)
}

func newEnvtestClient(t *testing.T) client.Client {
	t.Helper()
	if testCfg == nil {
		t.Fatal("CRD validation requires envtest. KUBEBUILDER_ASSETS is unset; " +
			"run via `make test`, not bare `go test ./...`.")
	}
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	cl, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return cl
}

// secretMountPath is the canonical valid bao path used across the
// CRD-validation cases. Centralized to satisfy goconst across repeats.
const secretMountPath = "secret"

func TestCRDValidation_OpenBaoSecretEngine_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	validBase := func() *v1alpha1.OpenBaoSecretEngine {
		m := &v1alpha1.OpenBaoSecretEngine{}
		m.Namespace = envtestNS
		m.Spec.Path = secretMountPath
		m.Spec.KvV2 = &v1alpha1.KvV2Spec{}
		return m
	}

	cases := []struct {
		name    string
		mutate  func(m *v1alpha1.OpenBaoSecretEngine)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline-kvV2",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) {},
			invalid: false,
			hint:    "the canonical valid kvV2 CR must admit",
		},
		{
			name: "valid-transit",
			mutate: func(m *v1alpha1.OpenBaoSecretEngine) {
				m.Spec.KvV2 = nil
				m.Spec.Transit = &v1alpha1.TransitSpec{}
				m.Spec.Path = "transit"
			},
			invalid: false,
			hint:    "transit slot must admit",
		},
		{
			name: "valid-pki",
			mutate: func(m *v1alpha1.OpenBaoSecretEngine) {
				m.Spec.KvV2 = nil
				m.Spec.PKI = &v1alpha1.PKISpec{}
				m.Spec.Path = "pki"
			},
			invalid: false,
			hint:    "pki slot must admit",
		},
		{
			name:    "no-engine-slot-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.KvV2 = nil },
			invalid: true,
			hint:    "XValidation: exactly one engine slot required",
		},
		{
			name: "two-slots-rejected",
			mutate: func(m *v1alpha1.OpenBaoSecretEngine) {
				m.Spec.Transit = &v1alpha1.TransitSpec{}
			},
			invalid: true,
			hint:    "XValidation: only one engine slot allowed",
		},
		{
			name:    "empty-path-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.Path = "" },
			invalid: true,
			hint:    "spec.path is required + MinLength=1",
		},
		{
			name:    "path-whitespace-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.Path = "secret with spaces" },
			invalid: true,
			hint:    "spec.path Pattern rejects whitespace",
		},
		{
			name:    "path-leading-slash-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.Path = "/secret" },
			invalid: true,
			hint:    "spec.path Pattern requires alphanumeric first character",
		},
		{
			name:    "path-nested-accepted",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.Path = "kv/cluster-a" },
			invalid: false,
			hint:    "spec.path Pattern must accept nested mount paths",
		},
		{
			name:    "openbaoNamespace-trailing-slash-accepted",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.OpenBaoNamespace = "acme/" },
			invalid: false,
			hint:    "trailing slash is conventional and must admit",
		},
		{
			name:    "openbaoNamespace-uppercase-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "openbaoNamespace pattern rejects uppercase",
		},
	}

	for i, tc := range cases {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			m := validBase()
			m.Name = fmt.Sprintf("mountval-%d", i)
			tc.mutate(m)

			err := cl.Create(ctx, m)
			if tc.invalid {
				require.Error(t, err, tc.hint)
				require.True(t, apierrors.IsInvalid(err),
					"%s — apiserver should reject with IsInvalid; got: %v", tc.hint, err)
			} else {
				require.NoError(t, err, tc.hint)
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{ObjectMeta: metav1.ObjectMeta{Name: m.Name, Namespace: envtestNS}})
			}
		})
	}
}
