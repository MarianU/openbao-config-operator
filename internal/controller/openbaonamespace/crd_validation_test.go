package openbaonamespace

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

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
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

// acmeNS is the canonical valid parent-namespace literal used across
// CRD-validation cases. Centralized to satisfy goconst across repeats.
const acmeNS = "acme/"

func TestCRDValidation_OpenBaoNamespace_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		mutate  func(n *v1alpha1.OpenBaoNamespace)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) {},
			invalid: false,
			hint:    "the canonical valid CR must admit",
		},
		{
			name:    "spec-name-uppercase-rejected",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.Name = "Bad_Name1" },
			invalid: true,
			hint:    "spec.name pattern must reject mixed case + underscore (anchored regex)",
		},
		{
			name:    "spec-name-leading-dash-rejected",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.Name = "-leading" },
			invalid: true,
			hint:    "spec.name pattern must reject leading dash",
		},
		{
			name:    "spec-name-clean-accepted",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.Name = "team-a" },
			invalid: false,
			hint:    "lowercase DNS-style name is the supported shape",
		},
		// Slash in spec.name is rejected by the Pattern marker because
		// nesting is achieved via spec.openbaoNamespace, not by embedding
		// the parent path in the name field.
		{
			name:    "spec-name-with-slash-rejected",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.Name = "a/b" },
			invalid: true,
			hint:    "spec.name Pattern must reject slashes — use spec.openbaoNamespace for nesting",
		},
		{
			name:    "openbaoNamespace-empty-accepted",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.OpenBaoNamespace = "" },
			invalid: false,
			hint:    "empty parent (root) must admit",
		},
		{
			name:    "openbaoNamespace-trailing-slash-accepted",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.OpenBaoNamespace = acmeNS },
			invalid: false,
			hint:    "nested-via-parent form must admit",
		},
		{
			name:    "openbaoNamespace-uppercase-rejected",
			mutate:  func(n *v1alpha1.OpenBaoNamespace) { n.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "openbaoNamespace pattern rejects uppercase",
		},
	}

	for i, tc := range cases {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			n := &v1alpha1.OpenBaoNamespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("nsval-%d", i),
					Namespace: envtestNS,
				},
			}
			tc.mutate(n)

			err := cl.Create(ctx, n)
			if tc.invalid {
				require.Error(t, err, tc.hint)
				require.True(t, apierrors.IsInvalid(err),
					"%s — apiserver should reject with IsInvalid; got: %v", tc.hint, err)
			} else {
				require.NoError(t, err, tc.hint)
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoNamespace{
					ObjectMeta: metav1.ObjectMeta{Name: n.Name, Namespace: envtestNS},
				})
			}
		})
	}
}
