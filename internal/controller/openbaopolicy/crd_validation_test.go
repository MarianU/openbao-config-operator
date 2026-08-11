package openbaopolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
)

// envtest uses the apiserver+etcd binaries pointed at by KUBEBUILDER_ASSETS;
// `make test` sets this. Without it, every envtest test in this file fails
// loudly (t.Fatal) rather than silently skipping — silent skips let CI
// invocations of `go test ./...` pass with zero CRD-validation coverage.
// Run via `make test`.

var (
	testEnv *envtest.Environment
	testCfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Crfake-based tests in this package run fine without envtest;
		// envtest tests will t.Fatal via newEnvtestClient.
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

const envtestNS = "default"

// CRD validation is enforced by the apiserver — crfake bypasses it. These
// tests load the actual generated CRD into envtest and assert that bad CRs
// are rejected with apierrors.IsInvalid. Catches regressions in the
// kubebuilder validation markers (anchored Pattern, MinLength, Required)
// that no go-level test would surface.
func TestCRDValidation_OpenBaoPolicy_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		mutate  func(p *v1alpha1.OpenBaoPolicy)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) {},
			invalid: false,
			hint:    "the canonical valid CR must admit",
		},
		{
			name:    "empty-policy-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.Policy = "" },
			invalid: true,
			hint:    "spec.policy is required + MinLength=1",
		},
		{
			name:    "name-uppercase-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.Name = "Bad_Name1" },
			invalid: true,
			hint:    "spec.name pattern must reject mixed case + underscore (anchored regex)",
		},
		{
			name:    "name-leading-dash-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.Name = "-leading-dash" },
			invalid: true,
			hint:    "spec.name pattern must reject leading dash",
		},
		{
			name:    "name-trailing-dash-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.Name = "trailing-dash-" },
			invalid: true,
			hint:    "spec.name pattern must reject trailing dash",
		},
		{
			name:    "name-clean-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.Name = "team-a-editor" },
			invalid: false,
			hint:    "lowercase DNS-style name is the supported shape",
		},
		// spec.openbaoNamespace coverage
		{
			name:    "openbaoNamespace-empty-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "" },
			invalid: false,
			hint:    "empty openbaoNamespace = root, must be accepted",
		},
		{
			name:    "openbaoNamespace-single-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "acme" },
			invalid: false,
			hint:    "single-segment without trailing slash must admit",
		},
		{
			name:    "openbaoNamespace-trailing-slash-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "acme/" },
			invalid: false,
			hint:    "trailing slash is conventional and must admit",
		},
		{
			name:    "openbaoNamespace-nested-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "team-a/dev/cluster-1" },
			invalid: false,
			hint:    "nested namespaces must admit",
		},
		{
			name:    "openbaoNamespace-uppercase-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "openbaoNamespace pattern rejects uppercase",
		},
		{
			name:    "openbaoNamespace-leading-slash-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "/acme" },
			invalid: true,
			hint:    "openbaoNamespace pattern rejects leading slash",
		},
		{
			name:    "openbaoNamespace-whitespace-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.OpenBaoNamespace = "acme name/" },
			invalid: true,
			hint:    "openbaoNamespace pattern rejects whitespace",
		},
		{
			name:    "deletionPolicy-retain-accepted",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.DeletionPolicy = "Retain" },
			invalid: false,
			hint:    "deletionPolicy enum must admit Retain",
		},
		{
			name:    "deletionPolicy-lowercase-rejected",
			mutate:  func(p *v1alpha1.OpenBaoPolicy) { p.Spec.DeletionPolicy = "delete" },
			invalid: true,
			hint:    "deletionPolicy enum is case-sensitive",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &v1alpha1.OpenBaoPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("crdval-%d-%s", i, sanitizeName(tc.name)),
					Namespace: envtestNS,
				},
				Spec: v1alpha1.OpenBaoPolicySpec{
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
				_ = cl.Delete(ctx, p)
			}
		})
	}
}

// The structural-schema default must stamp Delete onto a grant CR
// created without the field — grant kinds revoke on delete by default. The Go side treats empty as Delete regardless;
// this pins what users see on reads.
func TestCRDValidation_OpenBaoPolicy_DeletionPolicyDefaultsToDelete(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	p := &v1alpha1.OpenBaoPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "crdval-default-deletionpolicy", Namespace: envtestNS},
		Spec: v1alpha1.OpenBaoPolicySpec{
			Policy: `path "secret/data/foo/*" { capabilities = ["read"] }`,
		},
	}
	require.NoError(t, cl.Create(ctx, p))
	defer func() { _ = cl.Delete(ctx, p) }()

	var got v1alpha1.OpenBaoPolicy
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(p), &got))
	require.Equal(t, v1alpha1.DeletionPolicyDelete, got.Spec.DeletionPolicy,
		"apiserver must default deletionPolicy to Delete on grant kinds")
}

// sanitizeName makes a test case name safe to use as a metadata.name.
// envtest's apiserver enforces DNS-1123 subdomain rules; strip non-conforming
// characters so the test harness itself doesn't trip on the name we generate.
func sanitizeName(s string) string {
	r := strings.NewReplacer("_", "-", "/", "-", " ", "-")
	return strings.ToLower(r.Replace(s))
}
