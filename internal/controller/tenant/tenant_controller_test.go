package tenant

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apitypes "k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/internal/utils"
	mtocommon "github.com/stakater-ab/tenant-operator/api/common"
	mtov1beta3 "github.com/stakater-ab/tenant-operator/api/v1beta3"
)

const (
	testTenantName = "mytenant"
	testOBXNS      = "mto-extension-openbao-system"
	testOBXName    = "ex"
)

// ---- helpers ----

// newReconciler builds a reconciler bound to a fake k8s client seeded
// with the supplied objects. The Tenant reconciler no longer needs a
// bao client at the controller layer — emission is fully declarative,
// so the only dependency is the apiserver-side state.
func newReconciler(t *testing.T, objs ...client.Object) *TenantReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, mtov1beta3.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&extv1alpha1.OpenBaoExtension{}).
		Build()

	return &TenantReconciler{
		Client: cl,
		Scheme: scheme,
		Log:    logr.Discard(),
		env:    "prod",
	}
}

// reconcile drives one Reconcile cycle and returns the result.
func reconcile(t *testing.T, r *TenantReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
	require.NoError(t, err)
	return res
}

// obxReady builds the test OpenBaoExtension with AuthConfigured=True
// so Tenant reconcile passes the hard-gate. Default tenancy mode
// (path) can be overridden via the modify hook.
func obxReady(modify ...func(*extv1alpha1.OpenBaoExtension)) *extv1alpha1.OpenBaoExtension {
	ext := &extv1alpha1.OpenBaoExtension{
		ObjectMeta: metav1.ObjectMeta{Name: testOBXName, Namespace: testOBXNS},
		Spec: extv1alpha1.OpenBaoExtensionSpec{
			Tenancy: extv1alpha1.TenancySpec{Mode: extv1alpha1.TenancyPath},
		},
		Status: extv1alpha1.OpenBaoExtensionStatus{
			Conditions: []metav1.Condition{
				{
					Type:               extv1alpha1.CondAuthConfigured,
					Status:             metav1.ConditionTrue,
					Reason:             extv1alpha1.ReasonSuccess,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}
	for _, f := range modify {
		f(ext)
	}
	return ext
}

func sampleTenant(name string, withPrefix []string, withoutPrefix []string) *mtov1beta3.Tenant {
	t := &mtov1beta3.Tenant{}
	t.Name = name
	// Simulating what the apiserver would assign so owner-ref equality
	// has something to lock onto in the fake client.
	t.UID = apitypes.UID("tenant-uid-" + name)
	t.Spec.Namespaces = &mtov1beta3.Namespaces{}
	for _, n := range withPrefix {
		t.Spec.Namespaces.WithTenantPrefix = append(t.Spec.Namespaces.WithTenantPrefix, mtocommon.Namespace(n))
	}
	for _, n := range withoutPrefix {
		t.Spec.Namespaces.WithoutTenantPrefix = append(t.Spec.Namespaces.WithoutTenantPrefix, mtocommon.Namespace(n))
	}
	return t
}

func mustGet[T client.Object](t *testing.T, r *TenantReconciler, ns, name string, into T) T {
	t.Helper()
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, into))
	return into
}

// ---- hard gate ----

// Without an OpenBaoExtension carrying AuthConfigured=True, the
// reconciler must emit nothing and requeue at the standard backoff.
// Eliminates a race with the ClusterAuth controller where a Tenant
// could create k8s-auth roles against a not-yet-enabled bao mount.
func TestReconcile_HardGateBlocksWhenAuthNotConfigured(t *testing.T) {
	t.Parallel()
	ten := sampleTenant(testTenantName, []string{"ns-a"}, nil)
	ext := obxReady()
	// Force AuthConfigured=False to simulate ClusterAuth not having run.
	ext.Status.Conditions[0].Status = metav1.ConditionFalse

	r := newReconciler(t, ten, ext)
	res := reconcile(t, r, testTenantName)

	require.Equal(t, 30*time.Second, res.RequeueAfter, "must requeue at hard-gate backoff")

	// No sub-CRs should have been emitted.
	var policies extv1alpha1.OpenBaoPolicyList
	require.NoError(t, r.List(context.Background(), &policies))
	require.Empty(t, policies.Items, "no policies must be emitted while gated")
}

// ---- Mode B (path): emits Policy + Role with empty openbaoNamespace ----

// Mode B is the default when an OpenBaoExtension explicitly sets
// tenancy.mode=path. Each k8s namespace produces an OpenBaoPolicy +
// OpenBaoKubernetesAuthRole pair at the bao root, with tenant-prefixed
// bao names that match the imperative implementation byte-for-byte.
func TestReconcile_ModeB_EmitsPolicyAndRolePerNamespace(t *testing.T) {
	t.Parallel()
	ten := sampleTenant(testTenantName, []string{"namespace1", "namespace2"}, nil)
	ext := obxReady()

	r := newReconciler(t, ten, ext)
	reconcile(t, r, testTenantName)

	for _, k8sNS := range []string{"namespace1", "namespace2"} {
		nsFull := utils.NamespaceFull(testTenantName, k8sNS, true)
		policyName := utils.PolicyNameEditor(testTenantName, nsFull)

		policy := &extv1alpha1.OpenBaoPolicy{}
		mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "policy-"+nsFull), policy)
		require.Equal(t, policyName, policy.Spec.Name,
			"Mode B bao name must carry tenant prefix to disambiguate at root mount")
		require.Equal(t, "", policy.Spec.OpenBaoNamespace,
			"Mode B → spec.openbaoNamespace must be empty (root)")
		require.Contains(t, policy.Spec.Policy, "secret/data/tenants/"+testTenantName+"/prod/"+nsFull+"/*")

		role := &extv1alpha1.OpenBaoKubernetesAuthRole{}
		mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "role-"+nsFull), role)
		require.Equal(t, utils.RoleName(testTenantName, nsFull), role.Spec.Name)
		require.Equal(t, "", role.Spec.OpenBaoNamespace)
		require.ElementsMatch(t, []string{policyName}, role.Spec.Policies)
		require.ElementsMatch(t, []string{"default"}, role.Spec.TargetServiceAccounts)
		require.ElementsMatch(t, []string{nsFull}, role.Spec.TargetNamespaces.TargetNamespaces)
	}

	// Mode B must NOT emit OpenBaoNamespace or per-tenant OpenBaoSecretEngine.
	var nsList extv1alpha1.OpenBaoNamespaceList
	require.NoError(t, r.List(context.Background(), &nsList))
	require.Empty(t, nsList.Items, "Mode B must not emit OpenBaoNamespace")

	var seList extv1alpha1.OpenBaoSecretEngineList
	require.NoError(t, r.List(context.Background(), &seList))
	require.Empty(t, seList.Items, "Mode B must not emit per-tenant OpenBaoSecretEngine")
}

// withoutPrefix nsFull omits the tenant prefix from the namespace
// portion of the bao path. Only the bao naming differs from the
// with-prefix case; the controller logic is shared.
func TestReconcile_ModeB_WithoutTenantPrefix(t *testing.T) {
	t.Parallel()
	ten := sampleTenant("customera", nil, []string{"app-space"})
	ext := obxReady()

	r := newReconciler(t, ten, ext)
	reconcile(t, r, "customera")

	nsFull := utils.NamespaceFull("customera", "app-space", false)
	require.Equal(t, "app-space", nsFull, "withoutPrefix should not include tenant in nsFull")

	policy := &extv1alpha1.OpenBaoPolicy{}
	mustGet(t, r, testOBXNS, tenantChildName("customera", "policy-"+nsFull), policy)
	require.Equal(t, "customera-app-space-editor", policy.Spec.Name)
	require.Contains(t, policy.Spec.Policy, "secret/data/tenants/customera/prod/app-space/*")
}

// ---- Mode A (namespace): emits Namespace + KV secret engine + ns-scoped policies/roles ----

// Mode A emits an OpenBaoNamespace per tenant, a KV-v2 OpenBaoSecretEngine
// targeting that namespace, and ns-scoped Policy/Role children with short
// bao names (the bao namespace scopes them). The kubernetes auth mount
// itself is enabled by clusterauth at startup, not by per-tenant CRs.
func TestReconcile_ModeA_EmitsNamespaceAndSecretEngineAndScopedChildren(t *testing.T) {
	t.Parallel()
	ten := sampleTenant("acme", []string{"api"}, nil)
	ext := obxReady(func(e *extv1alpha1.OpenBaoExtension) {
		e.Spec.Tenancy.Mode = extv1alpha1.TenancyNamespace
	})

	r := newReconciler(t, ten, ext)
	reconcile(t, r, "acme")

	// OpenBaoNamespace
	bns := &extv1alpha1.OpenBaoNamespace{}
	mustGet(t, r, testOBXNS, tenantChildName("acme", "namespace"), bns)
	require.Equal(t, "acme", bns.Spec.Name, "bao namespace name = tenant")
	require.Equal(t, "", bns.Spec.OpenBaoNamespace, "tenant's bao namespace lives at root")

	// OpenBaoSecretEngine(KV)
	kvSE := &extv1alpha1.OpenBaoSecretEngine{}
	mustGet(t, r, testOBXNS, tenantChildName("acme", "kv"), kvSE)
	require.Equal(t, "secret", kvSE.Spec.Path)
	require.Equal(t, "acme/", kvSE.Spec.OpenBaoNamespace)
	require.NotNil(t, kvSE.Spec.KvV2, "KV secret engine must select kvV2 slot")
	require.Nil(t, kvSE.Spec.Transit)
	require.Nil(t, kvSE.Spec.PKI)

	// Mode A must NOT emit a per-tenant auth-method CR — clusterauth owns
	// the kubernetes auth mount globally.
	authSEName := tenantChildName("acme", "auth")
	authSE := &extv1alpha1.OpenBaoSecretEngine{}
	err := r.Get(context.Background(), types.NamespacedName{Namespace: testOBXNS, Name: authSEName}, authSE)
	require.True(t, apierrors.IsNotFound(err), "Mode A must not emit a tenant-scoped auth-mount CR")

	// Per-namespace policy + role
	nsFull := utils.NamespaceFull("acme", "api", true) // "acme-api"

	policy := &extv1alpha1.OpenBaoPolicy{}
	mustGet(t, r, testOBXNS, tenantChildName("acme", "policy-"+nsFull), policy)
	require.Equal(t, nsFull+"-editor", policy.Spec.Name,
		"Mode A bao policy name is short — bao ns scopes it")
	require.Equal(t, "acme/", policy.Spec.OpenBaoNamespace)

	role := &extv1alpha1.OpenBaoKubernetesAuthRole{}
	mustGet(t, r, testOBXNS, tenantChildName("acme", "role-"+nsFull), role)
	require.Equal(t, nsFull, role.Spec.Name,
		"Mode A bao role name is short — bao ns scopes it")
	require.Equal(t, "acme/", role.Spec.OpenBaoNamespace)
	require.ElementsMatch(t, []string{nsFull + "-editor"}, role.Spec.Policies)
}

// ---- token TTL + max TTL flow from OpenBaoExtension to emitted role ----

func TestReconcile_PropagatesTokenSettingsToRole(t *testing.T) {
	t.Parallel()
	ten := sampleTenant(testTenantName, []string{"ns-a"}, nil)
	ext := obxReady(func(e *extv1alpha1.OpenBaoExtension) {
		e.Spec.RBAC = extv1alpha1.RBACSpec{
			Token: extv1alpha1.RBACTokenSpec{
				TTL:    &metav1.Duration{Duration: time.Hour},
				MaxTTL: &metav1.Duration{Duration: 4 * time.Hour},
			},
		}
	})

	r := newReconciler(t, ten, ext)
	reconcile(t, r, testTenantName)

	nsFull := utils.NamespaceFull(testTenantName, "ns-a", true)
	role := &extv1alpha1.OpenBaoKubernetesAuthRole{}
	mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "role-"+nsFull), role)
	require.Equal(t, "3600s", role.Spec.TokenTTL)
	require.Equal(t, "14400s", role.Spec.TokenMaxTTL)
}

// ---- policy overrides + safety.allowDeletes flow into emitted policy body ----

func TestReconcile_PolicyOverrides_AffectEmittedBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		mutate         func(*extv1alpha1.OpenBaoExtension)
		mustContain    []string
		mustNotContain []string
	}{
		{
			name: "default editor (allowDeletes=false) omits delete from data caps",
			mutate: func(e *extv1alpha1.OpenBaoExtension) {
				// no overrides; default safety.AllowDeletes=false strips delete
			},
			mustContain:    []string{"create", "update", "read", "list"},
			mustNotContain: []string{`"delete"`},
		},
		{
			name: "explicit editor delete + safety=true preserves delete",
			mutate: func(e *extv1alpha1.OpenBaoExtension) {
				e.Spec.Safety.AllowDeletes = true
				e.Spec.PolicyOverrides = &extv1alpha1.PolicyOverrides{
					Editor: &extv1alpha1.PolicyCapabilityOverride{
						Capabilities: []extv1alpha1.PolicyCapability{
							extv1alpha1.CapCreate, extv1alpha1.CapRead,
							extv1alpha1.CapUpdate, extv1alpha1.CapDelete, extv1alpha1.CapList,
						},
					},
				}
			},
			mustContain: []string{`"delete"`},
		},
		{
			name: "editor override drops list → list cap omitted; metadata read still present",
			mutate: func(e *extv1alpha1.OpenBaoExtension) {
				e.Spec.PolicyOverrides = &extv1alpha1.PolicyOverrides{
					Editor: &extv1alpha1.PolicyCapabilityOverride{
						Capabilities: []extv1alpha1.PolicyCapability{
							extv1alpha1.CapCreate, extv1alpha1.CapRead, extv1alpha1.CapUpdate,
						},
					},
				}
			},
			// Without list, the metadata block contains only ["read"] (no
			// list cap on /*; no parent-list block emitted at all).
			mustContain:    []string{`metadata/tenants/mytenant/prod/mytenant-ns-a/*"`, `["read"]`},
			mustNotContain: []string{`"list"`},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ten := sampleTenant(testTenantName, []string{"ns-a"}, nil)
			ext := obxReady(tc.mutate)
			r := newReconciler(t, ten, ext)
			reconcile(t, r, testTenantName)

			nsFull := utils.NamespaceFull(testTenantName, "ns-a", true)
			policy := &extv1alpha1.OpenBaoPolicy{}
			mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "policy-"+nsFull), policy)

			for _, s := range tc.mustContain {
				require.Contains(t, policy.Spec.Policy, s,
					"emitted policy body must contain %q (case=%s)", s, tc.name)
			}
			for _, s := range tc.mustNotContain {
				require.NotContains(t, policy.Spec.Policy, s,
					"emitted policy body must not contain %q (case=%s)", s, tc.name)
			}
		})
	}
}

// ---- owner refs for cascading delete ----

// Every emitted sub-CR must carry a controller-owner ref to the
// Tenant so kubernetes-side garbage collection cascades on Tenant
// deletion. Without this, the deletion path leaks bao state.
func TestReconcile_EmittedChildrenCarryOwnerRefToTenant(t *testing.T) {
	t.Parallel()
	ten := sampleTenant(testTenantName, []string{"ns-a"}, nil)
	ext := obxReady(func(e *extv1alpha1.OpenBaoExtension) {
		e.Spec.Tenancy.Mode = extv1alpha1.TenancyNamespace
	})
	r := newReconciler(t, ten, ext)
	reconcile(t, r, testTenantName)

	for _, kind := range []string{"namespace", "kv"} {
		if kind == "namespace" {
			obj := &extv1alpha1.OpenBaoNamespace{}
			mustGet(t, r, testOBXNS, tenantChildName(testTenantName, kind), obj)
			require.True(t, ownedByTenant(obj, ten),
				"OpenBaoNamespace must carry controller-owner ref to Tenant")
			continue
		}
		obj := &extv1alpha1.OpenBaoSecretEngine{}
		mustGet(t, r, testOBXNS, tenantChildName(testTenantName, kind), obj)
		require.True(t, ownedByTenant(obj, ten),
			"OpenBaoSecretEngine(%s) must carry controller-owner ref to Tenant", kind)
	}

	nsFull := utils.NamespaceFull(testTenantName, "ns-a", true)
	policy := &extv1alpha1.OpenBaoPolicy{}
	mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "policy-"+nsFull), policy)
	require.True(t, ownedByTenant(policy, ten),
		"OpenBaoPolicy must carry controller-owner ref to Tenant")

	role := &extv1alpha1.OpenBaoKubernetesAuthRole{}
	mustGet(t, r, testOBXNS, tenantChildName(testTenantName, "role-"+nsFull), role)
	require.True(t, ownedByTenant(role, ten),
		"OpenBaoKubernetesAuthRole must carry controller-owner ref to Tenant")
}

// ---- orphan pruning ----

// Removing a k8s namespace from tenant.spec.namespaces must delete
// its emitted Policy + Role on the next reconcile. With owner refs
// alone, the orphan would persist until Tenant deletion — unwanted.
func TestReconcile_PrunesOrphanWhenNamespaceRemoved(t *testing.T) {
	t.Parallel()
	ten := sampleTenant(testTenantName, []string{"keep", "drop"}, nil)
	ext := obxReady()
	r := newReconciler(t, ten, ext)

	reconcile(t, r, testTenantName)

	nsFullDrop := utils.NamespaceFull(testTenantName, "drop", true)
	dropPolicyName := tenantChildName(testTenantName, "policy-"+nsFullDrop)
	dropRoleName := tenantChildName(testTenantName, "role-"+nsFullDrop)

	// Both children for "drop" exist after the first reconcile.
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: testOBXNS, Name: dropPolicyName}, &extv1alpha1.OpenBaoPolicy{}))
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: testOBXNS, Name: dropRoleName}, &extv1alpha1.OpenBaoKubernetesAuthRole{}))

	// User removes "drop" from spec.namespaces.
	curT := &mtov1beta3.Tenant{}
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: testTenantName}, curT))
	curT.Spec.Namespaces.WithTenantPrefix = []mtocommon.Namespace{"keep"}
	require.NoError(t, r.Update(context.Background(), curT))

	reconcile(t, r, testTenantName)

	// Both "drop" children must be gone.
	err := r.Get(context.Background(), types.NamespacedName{Namespace: testOBXNS, Name: dropPolicyName}, &extv1alpha1.OpenBaoPolicy{})
	require.True(t, apierrors.IsNotFound(err), "orphan OpenBaoPolicy should be pruned")
	err = r.Get(context.Background(), types.NamespacedName{Namespace: testOBXNS, Name: dropRoleName}, &extv1alpha1.OpenBaoKubernetesAuthRole{})
	require.True(t, apierrors.IsNotFound(err), "orphan OpenBaoKubernetesAuthRole should be pruned")

	// "keep" children must still be there.
	nsFullKeep := utils.NamespaceFull(testTenantName, "keep", true)
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{
		Namespace: testOBXNS, Name: tenantChildName(testTenantName, "policy-"+nsFullKeep),
	}, &extv1alpha1.OpenBaoPolicy{}), "non-orphan child must survive prune")
}

// Children owned by a different Tenant must not be pruned by this
// Tenant's reconcile. Owner UID is the only safe filter when k8s
// metadata.name happens to overlap (it shouldn't, but defense in
// depth).
func TestReconcile_DoesNotPruneOtherTenantsChildren(t *testing.T) {
	t.Parallel()
	tenA := sampleTenant("a", []string{"ns"}, nil)
	tenB := sampleTenant("b", []string{"ns"}, nil)
	ext := obxReady()
	r := newReconciler(t, tenA, tenB, ext)

	reconcile(t, r, "a")
	reconcile(t, r, "b")

	// Mutate Tenant a so its desired set shrinks; reconcile a.
	curA := &mtov1beta3.Tenant{}
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: "a"}, curA))
	curA.Spec.Namespaces.WithTenantPrefix = nil
	require.NoError(t, r.Update(context.Background(), curA))
	reconcile(t, r, "a")

	// Tenant b's child must still exist.
	nsFullB := utils.NamespaceFull("b", "ns", true)
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: testOBXNS, Name: tenantChildName("b", "policy-"+nsFullB)},
		&extv1alpha1.OpenBaoPolicy{}),
		"Tenant b's child must not be pruned by Tenant a's reconcile")
}

// ---- mode resolution ----

func TestResolveMode_DefaultsToNamespace(t *testing.T) {
	t.Parallel()
	require.Equal(t, extv1alpha1.TenancyNamespace, resolveMode(nil),
		"nil ext defaults to namespace per ADR-0001")

	ext := &extv1alpha1.OpenBaoExtension{}
	require.Equal(t, extv1alpha1.TenancyNamespace, resolveMode(ext),
		"empty mode defaults to namespace")

	ext.Spec.Tenancy.Mode = extv1alpha1.TenancyPath
	require.Equal(t, extv1alpha1.TenancyPath, resolveMode(ext),
		"explicit path mode is honoured")
}

// ---- helper coverage: leaseString edge cases ----

func TestLeaseString_NilEmpty(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", leaseString(nil))
}

func TestLeaseString_NegativeZeroes(t *testing.T) {
	t.Parallel()
	d := metav1.Duration{Duration: -5 * time.Second}
	require.Equal(t, "0s", leaseString(&d), "negative durations clamp to 0s")
}

// tenantChildName must be DNS-1123 (lowercase, alphanumeric+dash) so
// the apiserver accepts it as metadata.name. The function lower-cases
// the tenant input as a defense-in-depth — Tenant DNS rules already
// enforce lowercase, but a stale CRD or a fake client could bypass.
func TestTenantChildName_LowercasesTenant(t *testing.T) {
	t.Parallel()
	require.Equal(t, "myteam-policy-foo", tenantChildName("MyTeam", "policy-foo"))
	if !isDNSLabel(tenantChildName("MyTeam", "policy-foo")) {
		t.Fatal("tenantChildName output must be DNS-1123-compatible")
	}
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.':
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}
