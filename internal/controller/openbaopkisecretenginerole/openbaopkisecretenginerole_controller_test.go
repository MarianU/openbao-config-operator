package openbaopkisecretenginerole

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

const (
	envtestNS    = "default"
	pkiMount     = "pki"
	sharedRoleNm = "shared"
)

// fakeBao keys roles by (openbaoNs, mount, name) so the same role
// name on different mounts or namespaces is correctly distinct.
type fakeBao struct {
	roles map[string]baoclient.PKIRoleSpec

	writeErr  error
	readErr   error
	deleteErr error

	writes, reads, deletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{roles: map[string]baoclient.PKIRoleSpec{}}
}

func roleKey(ns, mount, name string) string { return ns + "|" + mount + "|" + name }

// ---- methods under test ----

func (f *fakeBao) WritePKIRole(ctx context.Context, mount, name string, spec baoclient.PKIRoleSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.roles[roleKey(baoclient.NamespaceFromOpts(opts), mount, name)] = spec
	return nil
}

func (f *fakeBao) ReadPKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	cur, ok := f.roles[roleKey(baoclient.NamespaceFromOpts(opts), mount, name)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return &cur, nil
}

func (f *fakeBao) DeletePKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.roles, roleKey(baoclient.NamespaceFromOpts(opts), mount, name))
	return nil
}

// ---- stubs for the rest of baoclient.Client ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) UpsertK8sRole(ctx context.Context, m, n string, s baoclient.K8sRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) EnableSecretEngine(ctx context.Context, m string, s baoclient.SecretEngineMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneSecretEngine(ctx context.Context, m string, s baoclient.SecretEngineMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetSecretEngineMount(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, m string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DisableAuthMount(ctx context.Context, m string, o ...baoclient.CallOption) error {
	return nil
}

// AuthMethod stubs — this controller does not exercise sys/auth tune.
func (f *fakeBao) EnableAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMethod(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return nil, baoclient.ErrNotFound
}

func (f *fakeBao) CreateNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GenerateRootPKI(ctx context.Context, m string, in baoclient.PKIRootGenerateInput, o ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}

// Intermediate-CA stubs — these controllers do not exercise the intermediate flow.
func (f *fakeBao) GenerateIntermediateCSR(ctx context.Context, mount string, in baoclient.PKIIntermediateGenerateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SignIntermediate(ctx context.Context, rootMount, csr string, in baoclient.PKISignIntermediateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ListPKIKeys(ctx context.Context, mount string, opts ...baoclient.CallOption) ([]string, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadPKICA(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WritePKIURLs(ctx context.Context, m string, in baoclient.PKIURLsInput, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIURLs(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return &baoclient.PKIURLsInput{}, nil
}

// Identity stubs — this controller does not exercise the identity API.
func (f *fakeBao) WriteIdentityGroup(ctx context.Context, spec baoclient.IdentityGroupSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, spec baoclient.IdentityGroupAliasSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

// ---- helpers ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoPKISecretEngineRoleReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoPKISecretEngineRole{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPKISecretEngineRoleFinalizer,
		Handlers:      OpenBaoPKISecretEngineRoleHandlers(cl, fb),
	}
	return &OpenBaoPKISecretEngineRoleReconciler{VaultResource: base}
}

func toClientObjects(in []runtime.Object) []client.Object {
	out := make([]client.Object, 0, len(in))
	for _, o := range in {
		if co, ok := o.(client.Object); ok {
			out = append(out, co)
		}
	}
	return out
}

func sampleRole(name string) *v1alpha1.OpenBaoPKISecretEngineRole {
	r := &v1alpha1.OpenBaoPKISecretEngineRole{}
	r.Name = name
	r.Namespace = envtestNS
	r.Spec.Path = pkiMount
	r.Spec.AllowedDomains = []string{"example.com"}
	r.Spec.AllowSubdomains = true
	r.Spec.ServerFlag = true
	return r
}

func reconcile(t *testing.T, r *OpenBaoPKISecretEngineRoleReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getRole(t *testing.T, r *OpenBaoPKISecretEngineRoleReconciler, name string) *v1alpha1.OpenBaoPKISecretEngineRole {
	t.Helper()
	var got v1alpha1.OpenBaoPKISecretEngineRole
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &got))
	return &got
}

func readyCond(t *testing.T, r *v1alpha1.OpenBaoPKISecretEngineRole) *metav1.Condition {
	t.Helper()
	for i := range r.Status.Conditions {
		if r.Status.Conditions[i].Type == resource.ConditionReady {
			return &r.Status.Conditions[i]
		}
	}
	return nil
}

// ---- tests ----

func TestPKIRole_CreatePath_WritesRole(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("web-server")
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name) // finalizer
	reconcile(t, r, role.Name) // write

	require.Equal(t, 1, fb.writes, "first reconcile must write the role")
	stored, ok := fb.roles[roleKey("", pkiMount, "web-server")]
	require.True(t, ok)
	require.Equal(t, []string{"example.com"}, stored.AllowedDomains)
	require.True(t, stored.AllowSubdomains)
	require.True(t, stored.ServerFlag)

	cond := readyCond(t, getRole(t, r, role.Name))
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

// IsValid rejects a spec with no allow* set; the controller's BaoWrite
// must NOT be reached.
func TestPKIRole_NoAllowSet_RejectedByIsValid_NoBaoWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := &v1alpha1.OpenBaoPKISecretEngineRole{}
	role.Name = "bad"
	role.Namespace = envtestNS
	role.Spec.Path = pkiMount
	// All allow* flags zero, allowedDomains empty.
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name) // finalizer
	reconcile(t, r, role.Name) // would write — but IsValid rejects

	require.Equal(t, 0, fb.writes, "IsValid rejection must short-circuit before BaoWrite")
	cond := readyCond(t, getRole(t, r, role.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

// Drift: spec change → bao re-write. Stable spec across reconciles →
// no extra writes (the comparator should treat sorted slices and
// default values as equivalent).
func TestPKIRole_DriftCorrection_OnSpecChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("web-server")
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name)
	reconcile(t, r, role.Name)
	require.Equal(t, 1, fb.writes)

	// Bump generation with a real spec change.
	cur := getRole(t, r, role.Name)
	cur.Spec.AllowedDomains = []string{"example.com", "test.com"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, role.Name)
	require.Equal(t, 2, fb.writes, "spec change must drive a re-write")

	stored := fb.roles[roleKey("", pkiMount, "web-server")]
	require.ElementsMatch(t, []string{"example.com", "test.com"}, stored.AllowedDomains)
}

// No-op reconcile after steady state: a second reconcile with the same
// spec must NOT trigger a write — the drift comparator returned true.
func TestPKIRole_DriftComparator_StableState_NoExtraWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("web-server")
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name)
	reconcile(t, r, role.Name)
	require.Equal(t, 1, fb.writes)

	// Reconcile again without any change.
	reconcile(t, r, role.Name)
	require.Equal(t, 1, fb.writes,
		"steady-state reconcile must not re-write — drift comparator returns true")
}

// IsDeletable=true: the bao role is removed on CR delete.
func TestPKIRole_DeletePath_RemovesBaoRole(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("web-server")
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name)
	reconcile(t, r, role.Name)
	require.Contains(t, fb.roles, roleKey("", pkiMount, "web-server"))

	cur := getRole(t, r, role.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, role.Name)

	require.Equal(t, 1, fb.deletes)
	require.NotContains(t, fb.roles, roleKey("", pkiMount, "web-server"))
}

// Same bao role name on different mounts must NOT collide.
func TestPKIRole_NameCollision_DifferentMountsDoNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	// Two distinct k8s CRs, same bao role name "shared", different
	// PKI mounts. Set spec.Name explicitly so BaoName is "shared" on
	// both regardless of metadata.name (which must be unique in k8s).
	a := sampleRole("k8s-a")
	a.Spec.Path = "pki-a"
	a.Spec.Name = sharedRoleNm
	a.UID = "uid-a"

	b := sampleRole("k8s-b")
	b.Spec.Path = "pki-b"
	b.Spec.Name = sharedRoleNm
	b.UID = "uid-b"

	r := buildReconciler(t, fb, a, b)

	reconcile(t, r, a.Name)
	reconcile(t, r, a.Name)
	reconcile(t, r, b.Name)
	reconcile(t, r, b.Name)

	require.Equal(t, 2, fb.writes, "both roles must write — different mounts, no collision")
	require.Contains(t, fb.roles, roleKey("", "pki-a", "shared"))
	require.Contains(t, fb.roles, roleKey("", "pki-b", "shared"))
}

// Same mount + same role name + different k8s namespace = collision.
func TestPKIRole_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleRole(sharedRoleNm)
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.Now()

	younger := &v1alpha1.OpenBaoPKISecretEngineRole{}
	younger.Name = "younger-cr"
	younger.Namespace = envtestNS
	younger.UID = "uid-younger"
	younger.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(1))
	younger.Spec.Path = pkiMount
	younger.Spec.Name = sharedRoleNm // same bao role name as older
	younger.Spec.AllowAnyName = true

	r := buildReconciler(t, fb, older, younger)

	reconcile(t, r, older.Name)
	reconcile(t, r, older.Name)
	require.Equal(t, 1, fb.writes)

	reconcile(t, r, younger.Name)
	reconcile(t, r, younger.Name)
	require.Equal(t, 1, fb.writes, "younger CR must NOT write — collision")

	cond := readyCond(t, getRole(t, r, younger.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// Rename across mount path: simultaneous spec.name + spec.path edit
// must clean up the previous role at the OLD path/OLD name. Without
// LastWrittenPath tracking, BaoDeleteIdentity would target the NEW
// path and 404 silently — orphaning the original role.
func TestPKIRole_Rename_AcrossMountPath_CleansAtOldPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("orig")
	role.Spec.Path = "pki-original"
	r := buildReconciler(t, fb, role)

	// Create + drift through one cycle so LastWrittenPath gets stamped.
	reconcile(t, r, role.Name)
	reconcile(t, r, role.Name)
	require.Contains(t, fb.roles, roleKey("", "pki-original", "orig"))

	got := getRole(t, r, role.Name)
	require.Equal(t, "pki-original", got.Status.LastWrittenPath,
		"BaoWrite must stamp LastWrittenPath via the StatusMutator")

	// Now rename BOTH name AND path in one edit.
	cur := getRole(t, r, role.Name)
	cur.Spec.Name = "renamed"
	cur.Spec.Path = "pki-new"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, role.Name)

	require.Contains(t, fb.roles, roleKey("", "pki-new", "renamed"),
		"new identity must be present in bao at the new mount")
	require.NotContains(t, fb.roles, roleKey("", "pki-original", "orig"),
		"previous identity at OLD path must be cleaned up — BaoDeleteIdentity must use LastWrittenPath, not Spec.Path")
}

// Rename: the previous role at the old name is deleted before the
// new identity is recorded. IsDeletable=true so this branch fires.
func TestPKIRole_Rename_CleansPreviousRole(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole("web-server")
	r := buildReconciler(t, fb, role)

	reconcile(t, r, role.Name)
	reconcile(t, r, role.Name)
	require.Contains(t, fb.roles, roleKey("", pkiMount, "web-server"))

	// Rename via spec.name.
	cur := getRole(t, r, role.Name)
	cur.Spec.Name = "renamed-role"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, role.Name)

	require.Contains(t, fb.roles, roleKey("", pkiMount, "renamed-role"),
		"new identity must be present in bao")
	require.NotContains(t, fb.roles, roleKey("", pkiMount, "web-server"),
		"previous identity must be cleaned up — RenameTracker fires BaoDeleteIdentity")

	got := getRole(t, r, role.Name)
	require.Equal(t, "renamed-role", got.Status.LastWrittenBaoName)
}

// Cert auth + JWT/OIDC stubs — this controller does not exercise them.
func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, mount string, spec baoclient.CertAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteCertAuthRole(ctx context.Context, mount, name string, spec baoclient.CertAuthRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, mount string, spec baoclient.JWTOIDCConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, mount string, spec baoclient.K8sAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteTransitKey(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) UpdateTransitKeyConfig(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DeleteTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
