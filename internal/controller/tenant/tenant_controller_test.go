package tenant

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	bao "github.com/stakater-ab/mto-extension-openbao/internal/utils"
	mtocommon "github.com/stakater-ab/tenant-operator/api/common"
	mtov1beta3 "github.com/stakater-ab/tenant-operator/api/v1beta3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testTenantName  = "mytenant"
	testDefaultName = "default"
)

// ---- Fake Bao client ----

type fakeBao struct {
	kvOK, authOK bool

	upsertedPolicies map[string]string
	upsertedRoles    map[string]baoclient.K8sRoleSpec
}

//nolint:unparam // keep kvOK flexible for future negative-case tests
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
func (f *fakeBao) EnableAuthMount(ctx context.Context, mount, typ string) error {
	f.authOK = true
	return nil
}

func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string) error {
	f.upsertedPolicies[name] = rules
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string) (string, error) {
	r, ok := f.upsertedPolicies[name]
	if !ok {
		return "", baoclient.ErrNotFound
	}
	return r, nil
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string) error {
	delete(f.upsertedPolicies, name)
	return nil
}
func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec) error {
	f.upsertedRoles[roleName] = spec
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string) (*baoclient.K8sRole, error) {
	spec, ok := f.upsertedRoles[roleName]
	if !ok {
		return nil, baoclient.ErrNotFound
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
func (f *fakeBao) DeleteK8sRole(ctx context.Context, _, roleName string) error {
	delete(f.upsertedRoles, roleName)
	return nil
}

// ---- NewTenantReconciler fatal startup ----

// The Tenant controller reads bao credentials at construction time and
// fails fast if they're missing or invalid. Operators saw delayed
// reconcile-time failures before this guard; the test pins both error
// paths so a future refactor can't quietly degrade back to "fail late".
func TestNewTenantReconciler_FailsFast(t *testing.T) {
	cases := []struct {
		name        string
		addr, token string
		wantErr     string
	}{
		{"both missing", "", "", "VAULT_ADDR/VAULT_TOKEN"},
		{"only addr missing", "", "tok", "VAULT_ADDR/VAULT_TOKEN"},
		{"only token missing", "http://x", "", "VAULT_ADDR/VAULT_TOKEN"},
		{"addr only whitespace", "  \t", "tok", "address is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VAULT_ADDR", tc.addr)
			t.Setenv("VAULT_TOKEN", tc.token)
			t.Setenv("BAO_ADDR", "")
			t.Setenv("BAO_TOKEN", "")
			r, err := NewTenantReconciler(nil)
			require.Error(t, err)
			require.Nil(t, r, "no reconciler should be returned on error")
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// ---- Tests ----

func TestReconcile_WithTenantPrefix(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme)) // <- register OpenBaoExtension

	// Seed a Tenant with withTenantPrefix
	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"namespace1", "namespace2"},
		},
	}

	// OBX ready so tenant reconciler passes the gate
	ext := obxReady("ns", "ex")

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext). // <- allow status handling for OBX in fake client
		Build()

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

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: testTenantName},
	})
	require.NoError(t, err)

	// Expect artifacts for namespace1
	ns1 := bao.NamespaceFull(testTenantName, "namespace1", true) // -> mytenant-namespace1
	pol1 := bao.PolicyNameEditor(testTenantName, ns1)            // -> mytenant-mytenant-namespace1-editor
	role1 := bao.RoleName(testTenantName, ns1)                   // -> mytenant-mytenant-namespace1

	body1, ok := fb.upsertedPolicies[pol1]
	require.True(t, ok, "policy for ns1 should be created")
	require.Contains(t, body1, fmt.Sprintf(`path "secret/data/tenants/%s/prod/%s/*"`, testTenantName, ns1))
	require.Contains(t, body1, fmt.Sprintf(`path "secret/metadata/tenants/%s/prod/%s/*"`, testTenantName, ns1))

	spec1, ok := fb.upsertedRoles[role1]
	require.True(t, ok, "role for ns1 should be created")
	require.ElementsMatch(t, []string{pol1}, spec1.Policies)
	require.ElementsMatch(t, []string{testDefaultName}, spec1.BoundServiceAccountNames)
	require.ElementsMatch(t, []string{ns1}, spec1.BoundServiceAccountNamespaces)

	// And for namespace2
	ns2 := bao.NamespaceFull(testTenantName, "namespace2", true)
	pol2 := bao.PolicyNameEditor(testTenantName, ns2)
	role2 := bao.RoleName(testTenantName, ns2)

	body2, ok := fb.upsertedPolicies[pol2]
	require.True(t, ok, "policy for ns2 should be created")
	require.Contains(t, body2, fmt.Sprintf(`path "secret/data/tenants/%s/prod/%s/*"`, testTenantName, ns2))

	_, ok = fb.upsertedRoles[role2]
	require.True(t, ok, "role for ns2 should be created")
}

func TestReconcile_WithoutTenantPrefix(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme)) // register OBX kind

	ten := &mtov1beta3.Tenant{}
	ten.Name = "customerA"
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithoutTenantPrefix: []mtocommon.Namespace{"app-space"},
		},
	}

	ext := obxReady("ns", "ex")

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext).
		Build()

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

	ns := bao.NamespaceFull("customerA", "app-space", false)
	require.Equal(t, "app-space", ns)

	pol := bao.PolicyNameEditor("customerA", ns)
	role := bao.RoleName("customerA", ns)

	body, ok := fb.upsertedPolicies[pol]
	require.True(t, ok)
	require.Contains(t, body, `path "secret/data/tenants/customera/prod/app-space/*"`)
	_, ok = fb.upsertedRoles[role]
	require.True(t, ok)
}

func TestReconcile_FailsWhenAuthMountMissing(t *testing.T) {
	t.Parallel()

	// Scheme needs BOTH Tenant and OpenBaoExtension types
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	// Tenant asking for one namespaced env
	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	// Seed an OBX with AuthConfigured=True so the tenant reconciler passes the gate
	ext := &extv1alpha1.OpenBaoExtension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ex",
			Namespace: "mto-extension-openbao-system",
		},
		Status: extv1alpha1.OpenBaoExtensionStatus{
			Conditions: []metav1.Condition{
				{
					Type:               "AuthConfigured",
					Status:             metav1.ConditionTrue,
					Reason:             "Success",
					Message:            "ready",
					LastTransitionTime: metav1.Now(),
					ObservedGeneration: 1,
				},
			},
		},
	}

	// Fake BAO: kv mount present, auth mount missing
	fb := newFakeBao(true, false)

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext). // important: let tests read/write status
		Build()

	r := &TenantReconciler{
		Client:    cl,
		Scheme:    scheme,
		Log:       logr.Discard(),
		baoClient: fb,
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}

	// Reconcile the tenant (cluster-scoped: no namespace in the request)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: testTenantName},
	})

	require.Error(t, err, "should error when kubernetes auth mount is absent")
	require.Empty(t, fb.upsertedRoles, "no roles should be created when auth mount is missing")
}

func TestReconcile_PropagatesTokenFromExtension(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))

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
	ext.Name = testDefaultName
	ext.Spec.RBAC.Token.TTL = dur("1h")
	ext.Spec.RBAC.Token.MaxTTL = dur("4h")
	ext.Spec.RBAC.Token.Renewable = boolp(false)

	ext.Status.Conditions = []metav1.Condition{
		{
			Type:               "AuthConfigured",
			Status:             metav1.ConditionTrue,
			Reason:             "Success",
			Message:            "ready",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	// Tenant
	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext).
		Build()
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

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testTenantName}})
	require.NoError(t, err)

	ns := bao.NamespaceFull(testTenantName, "ns", true)
	role := bao.RoleName(testTenantName, ns)

	spec, ok := fb.upsertedRoles[role]
	require.True(t, ok, "role should be created")

	// Expect seconds-formatted strings (per leaseString)
	require.Equal(t, "3600s", spec.TokenTTL)
	require.Equal(t, "14400s", spec.TokenMaxTTL)
	require.NotNil(t, spec.Renewable)
	require.Equal(t, false, *spec.Renewable)

	// assert leaf condition written by Tenant controller (requires OBX status subresource in client)
	var got extv1alpha1.OpenBaoExtension
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testDefaultName}, &got))

	var cond *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == "TenantsReconciled" {
			cond = &got.Status.Conditions[i]
			break
		}
	}
	require.NotNil(t, cond, "TenantsReconciled condition should be present")
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, "Success", cond.Reason)
	require.Equal(t, got.Generation, cond.ObservedGeneration)
}

func TestPolicyOverrides_EditorDeleteRespectsSafetyFalse(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	// Extension: editor explicitly includes delete, but safety=false should strip it.
	ext := &extv1alpha1.OpenBaoExtension{}
	ext.Name = testDefaultName
	ext.Spec.Safety.AllowDeletes = false
	ext.Spec.PolicyOverrides = &extv1alpha1.PolicyOverrides{
		Editor: &extv1alpha1.PolicyCapabilityOverride{
			Capabilities: []extv1alpha1.PolicyCapability{"create", "read", "update", "delete", "list"},
		},
	}

	ext.Status.Conditions = []metav1.Condition{
		{
			Type:               "AuthConfigured",
			Status:             metav1.ConditionTrue,
			Reason:             "Success",
			Message:            "ready",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext).
		Build()
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

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testTenantName}})
	require.NoError(t, err)

	ns := bao.NamespaceFull(testTenantName, "ns", true)
	pol := bao.PolicyNameEditor(testTenantName, ns)

	body, ok := fb.upsertedPolicies[pol]
	require.True(t, ok)

	// Data block present…
	require.Contains(t, body, fmt.Sprintf(`path "secret/data/tenants/%s/prod/%s/*"`, testTenantName, ns))
	// …but must NOT include delete due to safety=false.
	require.NotContains(t, body, `capabilities = ["create", "update", "read", "delete"]`)
	require.Contains(t, body, `capabilities = ["create", "update", "read"]`)

	// Metadata block: read + list still present.
	require.Contains(t, body, fmt.Sprintf(`path "secret/metadata/tenants/%s/prod/%s/*"`, testTenantName, ns))
	require.Contains(t, body, `capabilities = ["read", "list"]`)

	assertTenantsReconciledLeaf(t, r, testDefaultName)
}

func TestPolicyOverrides_EditorDeleteAllowedWhenSafetyTrue(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	// Extension: editor includes delete and safety=true => delete should appear on data/*.
	ext := &extv1alpha1.OpenBaoExtension{}
	ext.Name = testDefaultName
	ext.Spec.Safety.AllowDeletes = true
	ext.Spec.PolicyOverrides = &extv1alpha1.PolicyOverrides{
		Editor: &extv1alpha1.PolicyCapabilityOverride{
			Capabilities: []extv1alpha1.PolicyCapability{"create", "read", "update", "delete", "list"},
		},
	}

	ext.Status.Conditions = []metav1.Condition{
		{
			Type:               "AuthConfigured",
			Status:             metav1.ConditionTrue,
			Reason:             "Success",
			Message:            "ready",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext).
		Build()
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

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testTenantName}})
	require.NoError(t, err)

	ns := bao.NamespaceFull(testTenantName, "ns", true)
	pol := bao.PolicyNameEditor(testTenantName, ns)

	body, ok := fb.upsertedPolicies[pol]
	require.True(t, ok)

	// Data block includes delete now.
	require.Contains(t, body, fmt.Sprintf(`path "secret/data/tenants/%s/prod/%s/*"`, testTenantName, ns))
	require.Contains(t, body, `capabilities = ["create", "update", "read", "delete"]`)

	// Metadata block should remain read+list only (no metadata delete granted by our builder).
	require.Contains(t, body, fmt.Sprintf(`path "secret/metadata/tenants/%s/prod/%s/*"`, testTenantName, ns))
	require.Contains(t, body, `capabilities = ["read", "list"]`)

	assertTenantsReconciledLeaf(t, r, testDefaultName)
}

func TestPolicyOverrides_EditorNoList_RemovesParentListAndListCap(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	// Extension: editor has no list capability.
	ext := &extv1alpha1.OpenBaoExtension{}
	ext.Name = testDefaultName
	ext.Namespace = "mto-extension-openbao-system" // set a namespace
	ext.Spec.Safety.AllowDeletes = true            // explicit, but irrelevant here
	ext.Spec.PolicyOverrides = &extv1alpha1.PolicyOverrides{
		Editor: &extv1alpha1.PolicyCapabilityOverride{
			Capabilities: []extv1alpha1.PolicyCapability{"create", "read", "update"}, // no list
		},
	}
	// Seed status so tenant reconciler passes the gate
	ext.Status.Conditions = []metav1.Condition{
		{
			Type:               "AuthConfigured",
			Status:             metav1.ConditionTrue,
			Reason:             "Success",
			Message:            "ready",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	// Tenant with withTenantPrefix
	ten := &mtov1beta3.Tenant{}
	ten.Name = testTenantName
	ten.Spec = mtov1beta3.TenantSpec{
		Namespaces: &mtov1beta3.Namespaces{
			WithTenantPrefix: []mtocommon.Namespace{"ns"},
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ten, ext).
		WithStatusSubresource(ext).
		Build()

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

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: testTenantName},
	})
	require.NoError(t, err)

	// Policy assertions
	ns := bao.NamespaceFull(testTenantName, "ns", true)
	pol := bao.PolicyNameEditor(testTenantName, ns)

	body, ok := fb.upsertedPolicies[pol]
	require.True(t, ok)

	// Metadata/* block should be read-only (no list).
	require.Contains(t, body, fmt.Sprintf(`path "secret/metadata/tenants/%s/prod/%s/*"`, testTenantName, ns))
	require.Contains(t, body, `capabilities = ["read"]`)
	require.NotContains(t, body, `capabilities = ["read", "list"]`)

	// Parent metadata prefix "list" stanza should be absent when list not granted.
	require.NotContains(t, body, fmt.Sprintf(`path "secret/metadata/tenants/%s/prod/%s"`, testTenantName, ns))

	// Replace flaky helper with a precise condition check:
	var got extv1alpha1.OpenBaoExtensionList
	require.NoError(t, r.Client.List(context.Background(), &got))
	require.NotEmpty(t, got.Items)

	var found bool
	for _, c := range got.Items[0].Status.Conditions {
		if c.Type == extv1alpha1.CondTenantsReconciled && c.Status == metav1.ConditionTrue {
			found = true
			break
		}
	}
	require.True(t, found, "expected CondTenantsReconciled=True on the extension status")
}

func assertTenantsReconciledLeaf(t *testing.T, r *TenantReconciler, name string) {
	t.Helper()

	// Find the OBX by name across namespaces
	var lst extv1alpha1.OpenBaoExtensionList
	require.NoError(t, r.Client.List(context.Background(), &lst))

	var got *extv1alpha1.OpenBaoExtension
	for i := range lst.Items {
		if lst.Items[i].Name == name {
			got = &lst.Items[i]
			break
		}
	}
	require.NotNil(t, got, "expected an OpenBaoExtension named %q", name)

	// Find the TenantsReconciled condition and assert it is True/Success.
	var leaf *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == extv1alpha1.CondTenantsReconciled {
			leaf = &got.Status.Conditions[i]
			break
		}
	}
	require.NotNil(t, leaf, "TenantsReconciled should be present")
	require.Equal(t, metav1.ConditionTrue, leaf.Status)
	require.Equal(t, extv1alpha1.ReasonSuccess, leaf.Reason)
	require.Equal(t, got.Generation, leaf.ObservedGeneration)
}

func obxReady(ns, name string) *extv1alpha1.OpenBaoExtension {
	return &extv1alpha1.OpenBaoExtension{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status: extv1alpha1.OpenBaoExtensionStatus{
			Conditions: []metav1.Condition{
				{
					Type:               "AuthConfigured",
					Status:             metav1.ConditionTrue,
					Reason:             "Success",
					Message:            "ready",
					LastTransitionTime: metav1.Now(),
					ObservedGeneration: 1,
				},
			},
		},
	}
}
