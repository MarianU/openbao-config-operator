package vco

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

	vcov1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/vco/v1alpha1"
)

// envtest uses the apiserver+etcd binaries pointed at by KUBEBUILDER_ASSETS;
// `make test` sets this. If KUBEBUILDER_ASSETS is unset, every envtest test
// in this file fails loudly (t.Fatal) rather than skipping — silent skips
// let CI invocations of `go test ./...` pass with zero CRD-validation
// coverage. Run via `make test`.

var (
	testEnv *envtest.Environment
	testCfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Crfake-based tests in this package don't need envtest, so run
		// them. Envtest tests will t.Fatal via newEnvtestClient.
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
	require.NoError(t, vcov1alpha1.AddToScheme(scheme))
	cl, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return cl
}

// CRD validation is enforced by the apiserver — crfake bypasses it. These
// tests load the actual generated CRD into envtest and assert that bad CRs
// are rejected with apierrors.IsInvalid. Catches regressions in the
// kubebuilder validation markers (anchored Pattern, Enum, Required, etc.)
// that no go-level test would surface.
func TestCRDValidation_Policy_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	// Need a namespace; envtest's "default" exists.
	ns := "default"

	cases := []struct {
		name    string
		mutate  func(p *vcov1alpha1.Policy)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(p *vcov1alpha1.Policy) {},
			invalid: false,
			hint:    "the canonical valid CR must admit",
		},
		{
			name:    "empty-policy-rejected",
			mutate:  func(p *vcov1alpha1.Policy) { p.Spec.Policy = "" },
			invalid: true,
			hint:    "spec.policy is required + MinLength=1",
		},
		{
			name:    "name-uppercase-rejected",
			mutate:  func(p *vcov1alpha1.Policy) { p.Spec.Name = "Bad_Name1" },
			invalid: true,
			hint:    "spec.name pattern must reject mixed case + underscore (anchored regex)",
		},
		{
			name:    "name-leading-dash-rejected",
			mutate:  func(p *vcov1alpha1.Policy) { p.Spec.Name = "-leading-dash" },
			invalid: true,
			hint:    "spec.name pattern must reject leading dash",
		},
		{
			name:    "name-trailing-dash-rejected",
			mutate:  func(p *vcov1alpha1.Policy) { p.Spec.Name = "trailing-dash-" },
			invalid: true,
			hint:    "spec.name pattern must reject trailing dash",
		},
		{
			name:    "name-clean-accepted",
			mutate:  func(p *vcov1alpha1.Policy) { p.Spec.Name = "team-a-editor" },
			invalid: false,
			hint:    "lowercase DNS-style name is the supported shape",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &vcov1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("crdval-%d", i),
					Namespace: ns,
				},
				Spec: vcov1alpha1.PolicySpec{
					Policy: `path "secret/data/foo/*" { capabilities = ["read"] }`,
				},
			}
			tc.mutate(p)

			err := cl.Create(ctx, p)
			if tc.invalid {
				require.Error(t, err, tc.hint)
				require.True(t, apierrors.IsInvalid(err),
					"%s — apiserver should reject with IsInvalid; got: %v", tc.hint, err)
			} else {
				require.NoError(t, err, tc.hint)
				// Clean up so the next valid case in the table doesn't collide.
				_ = cl.Delete(ctx, p)
			}
		})
	}
}
