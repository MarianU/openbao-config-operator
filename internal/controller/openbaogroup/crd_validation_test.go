package openbaogroup

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

// TestCRDValidation_OpenBaoGroup_RejectsInvalid drives every kubebuilder
// marker the controller relies on through admission.
func TestCRDValidation_OpenBaoGroup_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoGroup {
		g := &v1alpha1.OpenBaoGroup{}
		g.Namespace = ns
		return g
	}

	cases := []struct {
		name    string
		mutate  func(g *v1alpha1.OpenBaoGroup)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(g *v1alpha1.OpenBaoGroup) {},
			invalid: false,
			hint:    "canonical valid spec must admit",
		},
		{
			name:    "specname-uppercase-rejected",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Name = "BAD" },
			invalid: true,
			hint:    "anchored Pattern on spec.name rejects uppercase",
		},
		{
			name:    "specname-underscore-rejected",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Name = "bad_name" },
			invalid: true,
			hint:    "Pattern on spec.name rejects underscore",
		},
		{
			name:    "specname-lowercase-accepted",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Name = "team-a" },
			invalid: false,
			hint:    "Pattern on spec.name accepts lowercase + hyphens",
		},
		{
			name:    "type-non-enum-rejected",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Type = "weird" },
			invalid: true,
			hint:    "Enum=internal;external on spec.type",
		},
		{
			name:    "type-internal-accepted",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Type = "internal" },
			invalid: false,
			hint:    "Enum on spec.type accepts internal",
		},
		{
			name:    "type-external-accepted",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.Type = "external" },
			invalid: false,
			hint:    "Enum on spec.type accepts external",
		},
		{
			name:    "openbaonamespace-uppercase-rejected",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
		{
			name:    "openbaonamespace-nested-accepted",
			mutate:  func(g *v1alpha1.OpenBaoGroup) { g.Spec.OpenBaoNamespace = "acme/sub/" },
			invalid: false,
			hint:    "Pattern on spec.openbaoNamespace accepts nested paths",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := validBase()
			g.Name = "t-" + tc.name
			tc.mutate(g)
			err := cl.Create(ctx, g)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoGroup{
					ObjectMeta: metav1.ObjectMeta{Name: g.Name, Namespace: ns},
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
