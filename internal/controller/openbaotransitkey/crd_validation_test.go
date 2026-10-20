package openbaotransitkey

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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

// Drives every kubebuilder marker the controller relies on through
// admission so a refactor that drops or weakens a marker fails this
// test rather than silently letting through bad specs.
func TestCRDValidation_OpenBaoTransitKey_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoTransitKey {
		k := &v1alpha1.OpenBaoTransitKey{}
		k.Namespace = ns
		k.Spec.Path = "transit"
		k.Spec.Name = "app-key"
		k.Spec.Type = "aes256-gcm96"
		return k
	}

	cases := []struct {
		name    string
		mutate  func(k *v1alpha1.OpenBaoTransitKey)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) {},
			invalid: false,
			hint:    "canonical valid spec must admit",
		},
		{
			name:    "specname-with-symbols-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Name = "team-a.key_1" },
			invalid: false,
			hint:    "Pattern on spec.name allows _-./",
		},
		{
			name:    "specname-leading-symbol-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Name = "-bad" },
			invalid: true,
			hint:    "anchored Pattern on spec.name forbids leading symbol",
		},
		{
			name:    "type-non-enum-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Type = "aes128" },
			invalid: true,
			hint:    "Enum on spec.type rejects unsupported algorithms",
		},
		{
			name:    "type-ed25519-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Type = typeEd25519 },
			invalid: false,
			hint:    "Enum on spec.type accepts ed25519",
		},
		{
			name:    "type-rsa3072-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Type = "rsa-3072" },
			invalid: false,
			hint:    "Enum on spec.type accepts rsa-3072",
		},
		{
			name:    "openbaonamespace-trailing-slash-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.OpenBaoNamespace = "team-a/" },
			invalid: false,
			hint:    "Pattern on spec.openbaoNamespace accepts trailing slash",
		},
		{
			name:    "openbaonamespace-uppercase-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.OpenBaoNamespace = "Team-A" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
		{
			name:    "autorotateperiod-pattern-30d-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.AutoRotatePeriod = "30d" },
			invalid: true,
			hint:    "Pattern on spec.autoRotatePeriod rejects 'd' (not a Go duration unit)",
		},
		{
			name:    "autorotateperiod-720h-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.AutoRotatePeriod = "720h" },
			invalid: false,
			hint:    "Pattern on spec.autoRotatePeriod accepts hours",
		},
		{
			name:    "autorotateperiod-zero-accepted",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.AutoRotatePeriod = "0" },
			invalid: false,
			hint:    "Pattern on spec.autoRotatePeriod accepts '0' for disabled",
		},
		{
			name: "keysize-too-small-rejected",
			mutate: func(k *v1alpha1.OpenBaoTransitKey) {
				v := 16
				k.Spec.KeySize = &v
			},
			invalid: true,
			hint:    "Minimum=32 on spec.keySize",
		},
		{
			name: "keysize-too-large-rejected",
			mutate: func(k *v1alpha1.OpenBaoTransitKey) {
				v := 1024
				k.Spec.KeySize = &v
			},
			invalid: true,
			hint:    "Maximum=512 on spec.keySize",
		},
		{
			name: "keysize-32-accepted",
			mutate: func(k *v1alpha1.OpenBaoTransitKey) {
				v := 32
				k.Spec.KeySize = &v
			},
			invalid: false,
			hint:    "spec.keySize accepts the lower bound",
		},
		// CLAUDE.md: every kubebuilder marker the controller relies on
		// must have a CRD-validation envtest case. These lock down the
		// remaining markers on spec.path and spec.name.
		//
		// MinLength=1 on spec.path can't be exercised here: spec.path
		// has `omitempty` + kubebuilder default "transit". Setting
		// Spec.Path = "" in Go strips the field from the JSON request,
		// which then triggers the default; the empty value never
		// reaches the MinLength check. The Pattern test below
		// transitively covers the empty-string case (Pattern requires
		// ≥1 character).
		{
			name: "path-too-long-rejected",
			mutate: func(k *v1alpha1.OpenBaoTransitKey) {
				k.Spec.Path = strings.Repeat("a", 129)
			},
			invalid: true,
			hint:    "MaxLength=128 on spec.path",
		},
		{
			name:    "path-leading-symbol-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Path = "-bad" },
			invalid: true,
			hint:    "anchored Pattern on spec.path forbids leading symbol",
		},
		{
			name:    "path-with-space-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Path = "trans it" },
			invalid: true,
			hint:    "Pattern on spec.path forbids whitespace",
		},
		{
			name:    "name-empty-rejected",
			mutate:  func(k *v1alpha1.OpenBaoTransitKey) { k.Spec.Name = "" },
			invalid: true,
			hint:    "Required + MinLength=1 on spec.name",
		},
		{
			name: "name-too-long-rejected",
			mutate: func(k *v1alpha1.OpenBaoTransitKey) {
				k.Spec.Name = strings.Repeat("a", 129)
			},
			invalid: true,
			hint:    "MaxLength=128 on spec.name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := validBase()
			k.Name = "t-" + tc.name
			tc.mutate(k)
			err := cl.Create(ctx, k)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoTransitKey{
					ObjectMeta: metav1.ObjectMeta{Name: k.Name, Namespace: ns},
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

// Defaults: spec.path defaults to "transit", spec.type defaults to
// "aes256-gcm96". A spec that omits both must admit and have the
// defaults stamped on retrieval.
func TestCRDDefaults_OpenBaoTransitKey(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	k := &v1alpha1.OpenBaoTransitKey{}
	k.Namespace = "default"
	k.Name = "defaults-test"
	k.Spec.Name = "defaults-key"
	// Omit Path and Type — defaults must apply.
	require.NoError(t, cl.Create(ctx, k))
	t.Cleanup(func() { _ = cl.Delete(ctx, k) })

	got := &v1alpha1.OpenBaoTransitKey{}
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: "default", Name: "defaults-test"}, got))
	require.Equal(t, "transit", got.Spec.Path)
	require.Equal(t, "aes256-gcm96", got.Spec.Type)
}
