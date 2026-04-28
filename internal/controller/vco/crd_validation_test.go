package vco

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
					Namespace: envtestNS,
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

// CRD validation for KubernetesAuthEngineRole. Same envtest harness as
// the Policy table above; the markers are enforced by the apiserver
// against the generated CRD manifest, so any drift between the Go
// kubebuilder annotations and the YAML installed in the cluster is
// caught here rather than by users at apply time.
// envtest namespace + auth-mount name reused across the KAER table; both
// are repeated more than three times in the cases below, which trips
// goconst when written as bare literals.
const (
	envtestNS        = "default"
	defaultAuthMount = "kubernetes"
)

func TestCRDValidation_KubernetesAuthEngineRole_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	validBase := func() *vcov1alpha1.KubernetesAuthEngineRole {
		k := &vcov1alpha1.KubernetesAuthEngineRole{}
		k.Namespace = envtestNS
		k.Spec.Path = defaultAuthMount
		k.Spec.VRole.Policies = []string{"editor"}
		k.Spec.VRole.TargetServiceAccounts = []string{"default"}
		k.Spec.TargetNamespaces.TargetNamespaces = []string{"team-a"}
		return k
	}

	cases := []struct {
		name    string
		mutate  func(k *vcov1alpha1.KubernetesAuthEngineRole)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) {},
			invalid: false,
			hint:    "the canonical valid CR must admit",
		},
		{
			name:    "empty-path-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Path = "" },
			invalid: true,
			hint:    "spec.path is required + MinLength=1",
		},
		{
			name:    "policies-empty-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.Policies = []string{} },
			invalid: true,
			hint:    "spec.policies has MinItems=1",
		},
		{
			name:    "spec-name-uppercase-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Name = "Bad_Name1" },
			invalid: true,
			hint:    "spec.name pattern must reject mixed case + underscore (anchored regex)",
		},
		{
			name:    "spec-name-leading-dash-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Name = "-leading" },
			invalid: true,
			hint:    "spec.name pattern must reject leading dash",
		},
		{
			name:    "spec-name-clean-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Name = "team-a-role" },
			invalid: false,
			hint:    "lowercase DNS-style name is the supported shape",
		},
		{
			name:    "alias-name-source-bad-enum-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.AliasNameSource = "garbage" },
			invalid: true,
			hint:    "spec.aliasNameSource has Enum",
		},
		{
			name:    "alias-name-source-good-enum-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.AliasNameSource = "serviceaccount_name" },
			invalid: false,
			hint:    "valid enum value must admit",
		},
		{
			name:    "token-type-bad-enum-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenType = "garbage" },
			invalid: true,
			hint:    "spec.tokenType has Enum",
		},
		{
			name:    "token-type-batch-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenType = "batch" },
			invalid: false,
			hint:    "batch is a valid tokenType",
		},
		{
			name:    "token-ttl-bare-integer-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenTTL = "3600" },
			invalid: true,
			hint:    "tokenTTL Pattern requires explicit unit (no bare integers)",
		},
		{
			name:    "token-ttl-typo-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenTTL = "1 hour" },
			invalid: true,
			hint:    "tokenTTL Pattern rejects whitespace + words",
		},
		{
			name:    "token-ttl-compound-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenTTL = "1h30m" },
			invalid: false,
			hint:    "tokenTTL Pattern must accept compound durations",
		},
		{
			name:    "token-ttl-units-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.VRole.TokenTTL = "500ms" },
			invalid: false,
			hint:    "tokenTTL Pattern must accept ms unit",
		},
		{
			name:    "path-whitespace-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Path = "kube netes" },
			invalid: true,
			hint:    "spec.path Pattern rejects whitespace",
		},
		{
			name:    "path-leading-slash-rejected",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Path = "/kubernetes" },
			invalid: true,
			hint:    "spec.path Pattern requires alphanumeric first character",
		},
		{
			name:    "path-nested-accepted",
			mutate:  func(k *vcov1alpha1.KubernetesAuthEngineRole) { k.Spec.Path = "dev/k8s-cluster-a" },
			invalid: false,
			hint:    "spec.path Pattern must accept nested mount paths bao supports",
		},
		{
			name: "spec-name-too-long-rejected",
			mutate: func(k *vcov1alpha1.KubernetesAuthEngineRole) {
				// 254 lowercase 'a's — one over the DNS-1123 ceiling.
				k.Spec.Name = strings.Repeat("a", 254)
			},
			invalid: true,
			hint:    "spec.name MaxLength=253",
		},
	}

	for i, tc := range cases {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			k := validBase()
			k.Name = fmt.Sprintf("kaerval-%d", i)
			tc.mutate(k)

			err := cl.Create(ctx, k)
			if tc.invalid {
				require.Error(t, err, tc.hint)
				require.True(t, apierrors.IsInvalid(err),
					"%s — apiserver should reject with IsInvalid; got: %v", tc.hint, err)
			} else {
				require.NoError(t, err, tc.hint)
				_ = cl.Delete(ctx, k)
			}
		})
	}
}
