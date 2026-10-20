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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
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
		{
			name:    "deletionPolicy-delete-accepted",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = "Delete" },
			invalid: false,
			hint:    "deletionPolicy enum must admit Delete",
		},
		{
			name:    "deletionPolicy-lowercase-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = "retain" },
			invalid: true,
			hint:    "deletionPolicy enum is case-sensitive",
		},
		{
			name:    "deletionPolicy-bogus-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = "Destroy" },
			invalid: true,
			hint:    "deletionPolicy enum rejects values outside Retain|Delete",
		},
		{
			name:    "deletionPolicy-uppercase-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = "DELETE" },
			invalid: true,
			hint:    "deletionPolicy enum rejects shouting case",
		},
		{
			name:    "deletionPolicy-leading-space-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = " Retain" },
			invalid: true,
			hint:    "deletionPolicy enum does not trim whitespace",
		},
		{
			name:    "deletionPolicy-trailing-space-rejected",
			mutate:  func(m *v1alpha1.OpenBaoSecretEngine) { m.Spec.DeletionPolicy = "Delete " },
			invalid: true,
			hint:    "deletionPolicy enum does not trim whitespace",
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

// A literal empty string is not the same as an absent field: YAML like
// `deletionPolicy: ""` (e.g. a broken helm value reaching a manifest)
// must be rejected by the enum, not silently defaulted. The typed
// client cannot express this — omitempty drops the field — so this
// goes through unstructured to put the empty string on the wire.
func TestCRDValidation_OpenBaoSecretEngine_DeletionPolicyExplicitEmptyRejected(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "security.mto.stakater.com/v1alpha1",
		"kind":       "OpenBaoSecretEngine",
		"metadata": map[string]interface{}{
			"name":      "mountval-empty-deletionpolicy",
			"namespace": envtestNS,
		},
		"spec": map[string]interface{}{
			"path":           secretMountPath,
			"kvV2":           map[string]interface{}{},
			"deletionPolicy": "",
		},
	}}
	err := cl.Create(ctx, u)
	require.Error(t, err, "explicit empty string must not be silently defaulted")
	require.True(t, apierrors.IsInvalid(err),
		"apiserver should reject with IsInvalid; got: %v", err)
}

// The structural-schema default must stamp Retain onto a data-bearing
// CR created without the field — what a pre-upgrade manifest looks
// like. The Go side treats empty as Retain regardless; this pins what
// users see on reads.
func TestCRDValidation_OpenBaoSecretEngine_DeletionPolicyDefaultsToRetain(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	m := &v1alpha1.OpenBaoSecretEngine{}
	m.Name = "mountval-default-deletionpolicy"
	m.Namespace = envtestNS
	m.Spec.Path = secretMountPath
	m.Spec.KvV2 = &v1alpha1.KvV2Spec{}
	require.NoError(t, cl.Create(ctx, m))
	defer func() {
		_ = cl.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{ObjectMeta: metav1.ObjectMeta{Name: m.Name, Namespace: envtestNS}})
	}()

	var got v1alpha1.OpenBaoSecretEngine
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(m), &got))
	require.Equal(t, v1alpha1.DeletionPolicyRetain, got.Spec.DeletionPolicy,
		"apiserver must default deletionPolicy to Retain on data-bearing kinds")
}
