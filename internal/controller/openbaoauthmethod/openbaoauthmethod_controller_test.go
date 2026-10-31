package openbaoauthmethod

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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

const (
	envtestNS = "default"
	uidA      = "uid-a"
	uidB      = "uid-b"
	mountPath = "oidc"
	mountType = "oidc"
	mountAcc  = "auth_oidc_abc123"
)

type fakeBao struct {
	// Embedded to carry the full Client interface; KV methods are
	// not exercised by this package and fall through to nil (panic if
	// called from a test, which would be a test bug).
	baoclient.Client
	mounts map[string]*baoclient.AuthMethodMount // key: ns|path

	enableErr  error
	tuneErr    error
	getErr     error
	disableErr error

	enables, tunes, gets, disables int
}

func newFakeBao() *fakeBao {
	return &fakeBao{mounts: map[string]*baoclient.AuthMethodMount{}}
}

func mountKey(ns, p string) string { return ns + "|" + p }

// ---- AuthMethod surface (the one this fake exists for) ----

func (f *fakeBao) EnableAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	f.enables++
	if f.enableErr != nil {
		return f.enableErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	f.mounts[mountKey(ns, mount)] = &baoclient.AuthMethodMount{
		Type:        spec.Type,
		Description: spec.Description,
		Accessor:    mountAcc,
		Config:      spec.Config,
	}
	return nil
}

func (f *fakeBao) TuneAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	f.tunes++
	if f.tuneErr != nil {
		return f.tuneErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cur, ok := f.mounts[mountKey(ns, mount)]
	if !ok {
		return baoclient.ErrNotFound
	}
	cur.Description = spec.Description
	cur.Config = spec.Config
	return nil
}

func (f *fakeBao) GetAuthMethod(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cur, ok := f.mounts[mountKey(ns, mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *cur
	return &cp, nil
}

func (f *fakeBao) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	f.disables++
	if f.disableErr != nil {
		return f.disableErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	delete(f.mounts, mountKey(ns, mount))
	return nil
}

// ---- minimal stubs for the rest of the Client surface ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) EnableSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return nil
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
func (f *fakeBao) UpsertK8sRole(ctx context.Context, am, rn string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, am, rn string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, am, rn string, opts ...baoclient.CallOption) error {
	return nil
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
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, ma string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
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

// ---- harness ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoAuthMethodReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoAuthMethod{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoAuthMethod]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoAuthMethodFinalizer,
		Handlers:      OpenBaoAuthMethodHandlers(cl, fb),
		Recorder:      record.NewFakeRecorder(32),
	}
	return &OpenBaoAuthMethodReconciler{VaultResource: base}
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

func sampleAuthMount() *v1alpha1.OpenBaoAuthMethod {
	m := &v1alpha1.OpenBaoAuthMethod{}
	m.Name = mountPath
	m.Namespace = envtestNS
	m.Spec.Path = mountPath
	m.Spec.Type = mountType
	return m
}

func runReconcile(t *testing.T, r *OpenBaoAuthMethodReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getMount(t *testing.T, r *OpenBaoAuthMethodReconciler, ns, name string) *v1alpha1.OpenBaoAuthMethod {
	t.Helper()
	var m v1alpha1.OpenBaoAuthMethod
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: ns, Name: name}, &m))
	return &m
}

func readyCond(m *v1alpha1.OpenBaoAuthMethod) *metav1.Condition {
	for i := range m.Status.Conditions {
		if m.Status.Conditions[i].Type == resource.ConditionReady {
			return &m.Status.Conditions[i]
		}
	}
	return nil
}

// First reconcile enables the mount and stamps the accessor on status.
func TestOpenBaoAuthMethod_CreatePath_EnablesAndStampsAccessor(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	res := runReconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 1, fb.enables)
	require.Equal(t, 0, fb.tunes, "first reconcile must enable, not tune")
	require.Equal(t, 5*time.Minute, res.RequeueAfter)

	got := getMount(t, r, envtestNS, m.Name)
	require.Equal(t, mountAcc, got.Status.MountAccessor)
	cond := readyCond(got)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

// Existing mount with matching state must not re-enable or re-tune.
func TestOpenBaoAuthMethod_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enables)

	for i := 0; i < 3; i++ {
		runReconcile(t, r, envtestNS, m.Name)
	}
	require.Equal(t, 1, fb.enables, "no second enable")
	require.Equal(t, 0, fb.tunes, "no tune when state matches")
}

// Description / config edits trigger tune (not re-enable).
func TestOpenBaoAuthMethod_DriftPath_RoutesToTune(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	m.Spec.Description = "v1"
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enables)

	cur := getMount(t, r, envtestNS, m.Name)
	cur.Spec.Description = "v2"
	require.NoError(t, r.Update(context.Background(), cur))
	runReconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 1, fb.enables, "must not re-enable on update")
	require.Equal(t, 1, fb.tunes, "drift must route to tune")
	stored := fb.mounts[mountKey("", mountPath)]
	require.Equal(t, "v2", stored.Description)
}

// Type immutability: spec edit type=jwt against an existing oidc mount
// surfaces as ReasonInternalError (not silently overwritten).
func TestOpenBaoAuthMethod_TypeImmutability(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enables)

	cur := getMount(t, r, envtestNS, m.Name)
	cur.Spec.Type = "jwt"
	require.NoError(t, r.Update(context.Background(), cur))

	res := runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	require.Equal(t, 0, fb.tunes, "type-change attempt must not call tune")

	cond := readyCond(getMount(t, r, envtestNS, m.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason)
	require.Contains(t, cond.Message, "immutable")
}

// OOB delete heals on next reconcile.
func TestOpenBaoAuthMethod_SelfHealOnOOBDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 1, fb.enables)

	delete(fb.mounts, mountKey("", mountPath))
	runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 2, fb.enables, "OOB delete must trigger re-enable")
}

// Deleting the CR under the default Retain policy releases the CR and
// leaves the auth mount in bao as an intentional, logged orphan.
func TestOpenBaoAuthMethod_DeletePath_DefaultRetains(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)

	cur := getMount(t, r, envtestNS, m.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 0, fb.disables, "Retain must never disable the auth mount")
	require.Contains(t, fb.mounts, mountKey("", mountPath),
		"the auth mount is an intentional orphan")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(),
			types.NamespacedName{Namespace: envtestNS, Name: m.Name},
			&v1alpha1.OpenBaoAuthMethod{})),
		"finalizer must release even though bao is untouched")
}

// spec.deletionPolicy=Delete opts back into destructive cleanup.
func TestOpenBaoAuthMethod_DeletePath_ExplicitDeleteDisables(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	m.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)

	cur := getMount(t, r, envtestNS, m.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, envtestNS, m.Name)

	require.Equal(t, 1, fb.disables)
	require.Empty(t, fb.mounts)
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(),
			types.NamespacedName{Namespace: envtestNS, Name: m.Name},
			&v1alpha1.OpenBaoAuthMethod{})))
}

// Unsupported type via IsValid (defense in depth on top of CRD enum).
func TestOpenBaoAuthMethod_RejectsUnsupportedType(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	m := sampleAuthMount()
	m.Spec.Type = "transit"
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	res := runReconcile(t, r, envtestNS, m.Name)

	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.enables)
	cond := readyCond(getMount(t, r, envtestNS, m.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestOpenBaoAuthMethod_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.enableErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	res := runReconcile(t, r, envtestNS, m.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(getMount(t, r, envtestNS, m.Name))
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

// Two CRs targeting the same (path, openbaoNamespace) collide.
func TestOpenBaoAuthMethod_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleAuthMount()
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleAuthMount()
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)

	runReconcile(t, r, "ns-b", mountPath)
	res := runReconcile(t, r, "ns-b", mountPath)
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.enables)
	cond := readyCond(getMount(t, r, "ns-b", mountPath))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)

	runReconcile(t, r, "ns-a", mountPath)
	runReconcile(t, r, "ns-a", mountPath)
	require.Equal(t, 1, fb.enables)
}

// Backfill recovers status.MountAccessor when status is wiped.
func TestOpenBaoAuthMethod_Backfill_RecoversAccessor(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with the mount the CR will adopt.
	fb.mounts[mountKey("", mountPath)] = &baoclient.AuthMethodMount{
		Type:        mountType,
		Description: "",
		Accessor:    "auth_oidc_pretty",
	}
	m := sampleAuthMount()
	r := buildReconciler(t, fb, m)

	runReconcile(t, r, envtestNS, m.Name)
	runReconcile(t, r, envtestNS, m.Name)

	got := getMount(t, r, envtestNS, m.Name)
	require.Equal(t, "auth_oidc_pretty", got.Status.MountAccessor,
		"Backfill must stamp the discovered accessor on a no-drift read")
	require.Equal(t, 0, fb.enables, "matching state must not trigger enable")
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
