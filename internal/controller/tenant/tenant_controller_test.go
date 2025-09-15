package tenant

import (
	"context"
	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	mtocommon "github.com/stakater-ab/tenant-operator/api/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	mtov1beta3 "github.com/stakater-ab/tenant-operator/api/v1beta3"

	// internal deps under your module
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	bao "github.com/stakater-ab/mto-extension-openbao/internal/utils"
)

// ---- Fake Bao client ----

type fakeBao struct {
	kvOK, authOK bool

	upsertedPolicies map[string]string
	upsertedRoles    map[string]baoclient.K8sRoleSpec
}

func newFakeBao(kvOK, authOK bool) *fakeBao {
	return &fakeBao{
		kvOK:             kvOK,
		authOK:           authOK,
		upsertedPolicies: map[string]string{},
		upsertedRoles:    map[string]baoclient.K8sRoleSpec{},
	}
}

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string) (bool, error) { return f.kvOK, nil }
func (f *fakeBao) CheckAuthMount(ctx context.Context, mount string) (bool, error) {
	return f.authOK, nil
}
func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string) error {
	f.upsertedPolicies[name] = rules
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string) (string, error) {
	r, ok := f.upsertedPolicies[name]
	if !ok {
		return "", apierrors.NewNotFound(schema.GroupResource{Group: "bao.test", Resource: "policy"}, name)
	}
	return r, nil
}

func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec) error {
	f.upsertedRoles[roleName] = spec
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string) (*baoclient.K8sRole, error) {
	spec, ok := f.upsertedRoles[roleName]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "bao.test", Resource: "role"}, roleName)
	}
	return &baoclient.K8sRole{
		Name:                          roleName,
		Policies:                      spec.Policies,
		BoundServiceAccountNames:      spec.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: spec.BoundServiceAccountNamespaces,
		TokenTTL:                      spec.TokenTTL,
		TokenMaxTTL:                   spec.TokenMaxTTL,
		Renewable:                     spec.Renewable,
	}, nil
}

// delete methods not needed yet for this unit test

// ---- Tests ----

func TestReconcile_WithTenantPrefix(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))

	// Seed a Tenant with withTenantPrefix
	ten := &mtov1beta3.Tenant{}
	ten.Name = "mytenant"
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"namespace1", "namespace2"},
		},
	}
	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(ten).Build()

	fb := newFakeBao(true, true) // kv mount ok, auth mount ok

	r := &TenantReconciler{
		Client:    cl,
		Scheme:    scheme,
		Log:       logr.Discard(),
		baoClient: fb,
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "mytenant"}})
	require.NoError(t, err)

	// Expect artifacts for namespace1
	ns1 := bao.NamespaceFull("mytenant", "namespace1", true) // -> mytenant-namespace1
	pol1 := bao.PolicyNameEditor("mytenant", ns1)            // -> mytenant-mytenant-namespace1-editor
	role1 := bao.RoleName("mytenant", ns1)                   // -> mytenant-mytenant-namespace1

	body1, ok := fb.upsertedPolicies[pol1]
	require.True(t, ok, "policy for ns1 should be created")
	require.Contains(t, body1, `path "secret/data/tenants/mytenant/prod/mytenant-namespace1/*"`)
	require.Contains(t, body1, `path "secret/metadata/tenants/mytenant/prod/mytenant-namespace1/*"`)

	spec1, ok := fb.upsertedRoles[role1]
	require.True(t, ok, "role for ns1 should be created")
	require.ElementsMatch(t, []string{pol1}, spec1.Policies)
	require.ElementsMatch(t, []string{"default"}, spec1.BoundServiceAccountNames)
	require.ElementsMatch(t, []string{ns1}, spec1.BoundServiceAccountNamespaces)

	// And for namespace2
	ns2 := bao.NamespaceFull("mytenant", "namespace2", true)
	pol2 := bao.PolicyNameEditor("mytenant", ns2)
	role2 := bao.RoleName("mytenant", ns2)

	body2, ok := fb.upsertedPolicies[pol2]
	require.True(t, ok, "policy for ns2 should be created")
	require.Contains(t, body2, `path "secret/data/tenants/mytenant/prod/mytenant-namespace2/*"`)

	_, ok = fb.upsertedRoles[role2]
	require.True(t, ok, "role for ns2 should be created")
}

func TestReconcile_WithoutTenantPrefix(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))

	ten := &mtov1beta3.Tenant{}
	ten.Name = "customerA"
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithoutTenantPrefix: []mtocommon.Namespace{"app-space"},
		},
	}
	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(ten).Build()
	fb := newFakeBao(true, true)

	r := &TenantReconciler{
		Client:    cl,
		Scheme:    scheme,
		Log:       logr.Discard(),
		baoClient: fb,
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "customerA"}})
	require.NoError(t, err)

	ns := bao.NamespaceFull("customerA", "app-space", false) // -> "app-space"
	require.Equal(t, "app-space", ns)

	pol := bao.PolicyNameEditor("customerA", ns) // -> "customera-app-space-editor"
	role := bao.RoleName("customerA", ns)        // -> "customera-app-space"

	body, ok := fb.upsertedPolicies[pol]
	require.True(t, ok)
	require.Contains(t, body, `path "secret/data/tenants/customera/prod/app-space/*"`)
	_, ok = fb.upsertedRoles[role]
	require.True(t, ok)
}

func TestReconcile_FailsWhenAuthMountMissing(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))

	ten := &mtov1beta3.Tenant{}
	ten.Name = "mytenant"
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{WithTenantPrefix: []mtocommon.Namespace{"ns"}},
	}
	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(ten).Build()

	fb := newFakeBao(true, false) // kv OK, auth mount missing

	r := &TenantReconciler{
		Client:    cl,
		Scheme:    scheme,
		Log:       logr.Discard(),
		baoClient: fb,
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "mytenant"}})
	require.Error(t, err, "should error when kubernetes auth mount is absent")
	require.Empty(t, fb.upsertedRoles, "no roles should be created when auth mount is missing")
}

func TestReconcile_PropagatesTokenFromExtension(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))

	// Import your real extension API package:
	// extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	// OpenBaoExtension with rbac.token set
	dur := func(s string) *metav1.Duration {
		d, err := time.ParseDuration(s)
		require.NoError(t, err)
		md := metav1.Duration{Duration: d}
		return &md
	}
	boolp := func(b bool) *bool { return &b }

	ext := &extv1alpha1.OpenBaoExtension{}
	ext.Name = "default"
	ext.Spec.RBAC.Token.TTL = dur("1h")
	ext.Spec.RBAC.Token.MaxTTL = dur("4h")
	ext.Spec.RBAC.Token.Renewable = boolp(false)

	// Tenant
	ten := &mtov1beta3.Tenant{}
	ten.Name = "mytenant"
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(ten, ext).Build()
	fb := newFakeBao(true, true)

	r := &TenantReconciler{
		Client:    cl,
		Scheme:    scheme,
		Log:       logr.Discard(),
		baoClient: fb,
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "mytenant"}})
	require.NoError(t, err)

	ns := bao.NamespaceFull("mytenant", "ns", true)
	role := bao.RoleName("mytenant", ns)

	spec, ok := fb.upsertedRoles[role]
	require.True(t, ok, "role should be created")

	// Expect seconds-formatted strings (per leaseString)
	require.Equal(t, "3600s", spec.TokenTTL)
	require.Equal(t, "14400s", spec.TokenMaxTTL)
	require.NotNil(t, spec.Renewable)
	require.Equal(t, false, *spec.Renewable)
}
