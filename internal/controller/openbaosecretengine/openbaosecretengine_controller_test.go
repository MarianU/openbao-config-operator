package openbaosecretengine

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

const envtestNS = "default"

// Test-only stable UID literals — extracted to satisfy goconst.
const (
	uidA = "uid-a"
	uidB = "uid-b"

	// Stable k8s namespace literals reused across collision cases.
	nsA = "ns-a"
	nsB = "ns-b"
)

// ---- fake bao ----

// fakeBao implements baoclient.Client with an in-memory mount registry,
// keyed by (openbaoNamespace, kind, path) so bao's namespace + endpoint
// isolation is correctly modeled. Policies and roles are stubbed out —
// the OpenBaoSecretEngine controller doesn't touch them.
type fakeBao struct {
	// secretMounts keyed as "<openbaoNs>|<path>".
	secretMounts map[string]baoclient.SecretEngineMount

	// Error injection.
	enableSecretErr  error
	tuneSecretErr    error
	getSecretErr     error
	disableSecretErr error
	disableAuthErr   error

	// Call counters.
	enableSecret, tuneSecret, getSecret, disableSecret int
	disableAuth                                        int
}

func newFakeBao() *fakeBao {
	return &fakeBao{
		secretMounts: map[string]baoclient.SecretEngineMount{},
	}
}

func mountKey(ns, path string) string { return ns + "|" + path }

// Existing methods stubbed; mount controller doesn't touch policies/roles.
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
func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
	return nil
}

// Mount lifecycle — the actual surface this fake exists to model.

func (f *fakeBao) EnableSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	f.enableSecret++
	if f.enableSecretErr != nil {
		return f.enableSecretErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	f.secretMounts[mountKey(ns, mount)] = baoclient.SecretEngineMount(spec)
	return nil
}

// TuneSecretEngine updates description / options on an already-existing
// mount. The fake mirrors real bao: type is mount-immutable so we
// preserve whatever was stored on enable; description and options are
// overwritten verbatim.
func (f *fakeBao) TuneSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	f.tuneSecret++
	if f.tuneSecretErr != nil {
		return f.tuneSecretErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cur, ok := f.secretMounts[mountKey(ns, mount)]
	if !ok {
		return baoclient.ErrNotFound
	}
	cur.Description = spec.Description
	cur.Options = spec.Options
	f.secretMounts[mountKey(ns, mount)] = cur
	return nil
}

func (f *fakeBao) GetSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	f.getSecret++
	if f.getSecretErr != nil {
		return nil, f.getSecretErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	got, ok := f.secretMounts[mountKey(ns, mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return &got, nil
}

func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	f.disableSecret++
	if f.disableSecretErr != nil {
		return f.disableSecretErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	delete(f.secretMounts, mountKey(ns, mount))
	return nil
}

func (f *fakeBao) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	f.disableAuth++
	if f.disableAuthErr != nil {
		return f.disableAuthErr
	}
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
func (f *fakeBao) CreateNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

func (f *fakeBao) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return &baoclient.PKIURLsInput{}, nil
}

func (f *fakeBao) WritePKIRole(ctx context.Context, mount, name string, spec baoclient.PKIRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
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

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoSecretEngineReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoSecretEngine{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoSecretEngine]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoSecretEngineFinalizer,
		Handlers:      OpenBaoSecretEngineHandlers(cl, fb),
	}
	return &OpenBaoSecretEngineReconciler{VaultResource: base}
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

func sampleKvV2Mount(name string) *v1alpha1.OpenBaoSecretEngine {
	m := &v1alpha1.OpenBaoSecretEngine{}
	m.Name = name
	m.Namespace = envtestNS
	m.Spec.Path = secretMountPath
	m.Spec.Description = "tenant kv-v2"
	m.Spec.KvV2 = &v1alpha1.KvV2Spec{}
	return m
}

func reconcile(t *testing.T, r *OpenBaoSecretEngineReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getMount(t *testing.T, r *OpenBaoSecretEngineReconciler, ns, name string) *v1alpha1.OpenBaoSecretEngine {
	t.Helper()
	var m v1alpha1.OpenBaoSecretEngine
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &m))
	return &m
}

func readyCond(t *testing.T, m *v1alpha1.OpenBaoSecretEngine) *metav1.Condition {
	t.Helper()
	for i := range m.Status.Conditions {
		if m.Status.Conditions[i].Type == resource.ConditionReady {
			return &m.Status.Conditions[i]
		}
	}
	return nil
}

// ---- create / edit / drift / delete ----

func TestOpenBaoSecretEngine_CreatePath_KvV2(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name) // finalizer
	require.Contains(t, getMount(t, r, envtestNS, m.Name).Finalizers, OpenBaoSecretEngineFinalizer)

	reconcile(t, r, envtestNS, m.Name) // write
	require.Equal(t, 1, fb.enableSecret)
	stored, ok := fb.secretMounts[mountKey("", secretMountPath)]
	require.True(t, ok)
	require.Equal(t, "kv", stored.Type)
	require.Equal(t, "tenant kv-v2", stored.Description)
	require.Equal(t, "2", stored.Options["version"])

	cond := readyCond(t, getMount(t, r, envtestNS, m.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

func TestOpenBaoSecretEngine_EditPath_RewritesOnDescriptionChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enableSecret)
	require.Equal(t, 0, fb.tuneSecret, "first reconcile creates the mount via enable, no tune yet")

	cur := getMount(t, r, envtestNS, m.Name)
	cur.Spec.Description = "updated description"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enableSecret, "second pass must NOT re-enable (bao would 400 'already in use')")
	require.Equal(t, 1, fb.tuneSecret, "description change must drive a tune call on the existing mount")
	require.Equal(t, "updated description", fb.secretMounts[mountKey("", secretMountPath)].Description)
}

// Out-of-band drift on the description triggers re-upsert on next
// reconcile (matches Policy / KAER drift semantics).
func TestOpenBaoSecretEngine_DriftCorrection_DescriptionEdit(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enableSecret)

	stored := fb.secretMounts[mountKey("", secretMountPath)]
	stored.Description = "tampered"
	fb.secretMounts[mountKey("", secretMountPath)] = stored

	// Bump generation to trigger reconcile (the controller uses
	// GenerationChangedPredicate; an annotation change wouldn't fire,
	// matching the drift behaviour documented in the project memory).
	cur := getMount(t, r, envtestNS, m.Name)
	cur.Spec.Description = "tenant kv-v2-revised" // forces a new generation
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enableSecret, "second pass uses tune, not enable, on the existing mount")
	require.Equal(t, 1, fb.tuneSecret, "tampered description must be corrected via tune")
	require.Equal(t, "tenant kv-v2-revised", fb.secretMounts[mountKey("", secretMountPath)].Description)
}

// Engine type is immutable in bao. A CR that flips kvV2 → transit on
// an existing kv mount must NOT silently report Ready=True — bao
// rejects every "fix" attempt because mounts can't change type
// in-place. The controller surfaces a clear error so the user knows
// to delete + recreate.
func TestOpenBaoSecretEngine_EngineTypeChange_RejectedClearly(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, "kv", fb.secretMounts[mountKey("", secretMountPath)].Type)

	// Flip the spec from kvV2 to transit on the same path.
	cur := getMount(t, r, envtestNS, m.Name)
	cur.Spec.KvV2 = nil
	cur.Spec.Transit = &v1alpha1.TransitSpec{}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, envtestNS, m.Name)

	cond := readyCond(t, getMount(t, r, envtestNS, m.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status,
		"engine-type change is silently impossible in bao — CR must NOT claim Ready=True")
	require.Contains(t, cond.Message, "engine type is immutable",
		"error message must point the user at the recreate workaround")
	require.Equal(t, "kv", fb.secretMounts[mountKey("", secretMountPath)].Type,
		"bao mount type must stay 'kv' — no half-applied state")
}

func TestOpenBaoSecretEngine_DeletePath_KvV2(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enableSecret)

	cur := getMount(t, r, envtestNS, m.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 1, fb.disableSecret, "DisableSecretEngineMount must run once on delete")
	require.NotContains(t, fb.secretMounts, mountKey("", secretMountPath))

	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: m.Name}, &v1alpha1.OpenBaoSecretEngine{})
	require.True(t, apierrors.IsNotFound(err))
}

func TestOpenBaoSecretEngine_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.enableSecretErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	m := sampleKvV2Mount("kv")
	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	res := reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getMount(t, r, envtestNS, m.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

// Two CRs targeting the same (openbaoNamespace, kind, path) tuple
// collide; older CreationTimestamp wins.
func TestOpenBaoSecretEngine_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleKvV2Mount("kv-older")
	older.Namespace = nsA
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))
	older.Spec.Description = "older"

	newer := sampleKvV2Mount("kv-newer")
	newer.Namespace = nsB
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.Description = "newer"

	r := buildReconciler(t, fb, older, newer)

	reconcile(t, r, nsA, "kv-older")
	reconcile(t, r, nsA, "kv-older")
	require.Equal(t, 1, fb.enableSecret)

	reconcile(t, r, nsB, "kv-newer")
	res := reconcile(t, r, nsB, "kv-newer")
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter,
		"collision is a stable state — loser should requeue at PeriodicInterval, not ErrorBackoff")
	require.Equal(t, 1, fb.enableSecret, "newer (loser) must not have written")

	stored := fb.secretMounts[mountKey("", secretMountPath)]
	require.Equal(t, "older", stored.Description, "older's description must remain")

	cond := readyCond(t, getMount(t, r, nsB, "kv-newer"))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// Same path in two different bao endpoints (sys/mounts/secret vs
// sys/auth/secret) is not a collision.
// Same path in different OpenBao namespaces is not a collision.
func TestOpenBaoSecretEngine_NameCollision_DifferentOpenBaoNamespaceDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleKvV2Mount("kv-a")
	a.Namespace = nsA
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := sampleKvV2Mount("kv-b")
	b.Namespace = nsB
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildReconciler(t, fb, a, b)

	reconcile(t, r, nsA, "kv-a")
	reconcile(t, r, nsA, "kv-a")
	reconcile(t, r, nsB, "kv-b")
	reconcile(t, r, nsB, "kv-b")

	require.Equal(t, 2, fb.enableSecret)
	require.Contains(t, fb.secretMounts, mountKey("acme/", secretMountPath))
	require.Contains(t, fb.secretMounts, mountKey("globex/", secretMountPath))
}

// Ready=False should skip BaoDelete to avoid stranding a CR in
// Terminating when no bao state was ever written.
func TestOpenBaoSecretEngine_DeleteSkipsBaoIfNeverWritten(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := &v1alpha1.OpenBaoSecretEngine{}
	m.Name = "two-slots"
	m.Namespace = envtestNS
	m.Spec.Path = secretMountPath
	// Force IsValid to reject by setting two slots.
	m.Spec.KvV2 = &v1alpha1.KvV2Spec{}
	m.Spec.Transit = &v1alpha1.TransitSpec{}

	r := buildReconciler(t, fb, m)

	reconcile(t, r, envtestNS, m.Name)
	reconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 0, fb.enableSecret)

	cond := readyCond(t, getMount(t, r, envtestNS, m.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)

	cur := getMount(t, r, envtestNS, m.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 0, fb.disableSecret, "BaoDelete must be skipped when status.baoWritten=false")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: m.Name}, &v1alpha1.OpenBaoSecretEngine{})))
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
