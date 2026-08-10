package openbaopkisecretenginerole

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
)

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

// TestCRDValidation_OpenBaoPKIRole_RejectsInvalid drives every
// kubebuilder marker the controller relies on through admission.
func TestCRDValidation_OpenBaoPKIRole_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoPKISecretEngineRole {
		r := &v1alpha1.OpenBaoPKISecretEngineRole{}
		r.Namespace = ns
		r.Spec.Path = "pki"
		r.Spec.AllowAnyName = true
		return r
	}

	cases := []struct {
		name    string
		mutate  func(r *v1alpha1.OpenBaoPKISecretEngineRole)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) {},
			invalid: false,
			hint:    "canonical valid spec must admit",
		},
		{
			name:    "empty-path-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.Path = "" },
			invalid: true,
			hint:    "MinLength=1 on spec.path",
		},
		{
			name:    "specname-uppercase-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.Name = "BAD" },
			invalid: true,
			hint:    "anchored Pattern on spec.name rejects uppercase",
		},
		{
			name:    "specname-lowercase-accepted",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.Name = "web-server" },
			invalid: false,
			hint:    "Pattern on spec.name accepts lowercase + hyphens",
		},
		{
			name:    "keytype-non-enum-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.KeyType = "dsa" },
			invalid: true,
			hint:    "Enum=rsa;ec;ed25519;any on spec.keyType",
		},
		{
			name:    "keytype-any-accepted",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.KeyType = "any" },
			invalid: false,
			hint:    "Enum on spec.keyType allows 'any'",
		},
		{
			name:    "keybits-too-large-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.KeyBits = 16384 },
			invalid: true,
			hint:    "Maximum=8192 on spec.keyBits",
		},
		{
			name:    "ttl-pattern-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.TTL = "1 week" },
			invalid: true,
			hint:    "Pattern on spec.ttl rejects whitespace/word forms",
		},
		{
			name:    "ttl-pattern-accepted",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.TTL = "720h" },
			invalid: false,
			hint:    "Pattern on spec.ttl accepts bao duration shape",
		},
		{
			name:    "maxttl-pattern-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.MaxTTL = "always" },
			invalid: true,
			hint:    "Pattern on spec.maxTtl rejects words",
		},
		{
			name:    "openbaonamespace-uppercase-rejected",
			mutate:  func(r *v1alpha1.OpenBaoPKISecretEngineRole) { r.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validBase()
			r.Name = "t-" + tc.name
			tc.mutate(r)
			err := cl.Create(ctx, r)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineRole{
					ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: ns},
				})
			})
			if tc.invalid {
				require.Error(t, err, tc.hint)
			} else {
				require.NoError(t, err, tc.hint)
			}
		})
	}
}
