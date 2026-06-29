package openbaoidentitytokenrole

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

const (
	envtestNS = "default"
	uidA      = "uid-a"
	uidB      = "uid-b"
	roleName  = "aws-tokens"
)

// fakeBao stores token roles keyed by (openbaoNamespace, name).
type fakeBao struct {
	roles map[string]*baoclient.IdentityTokenRoleSpec

	writeErr  error
	readErr   error
	deleteErr error

	writes, reads, deletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{roles: map[string]*baoclient.IdentityTokenRoleSpec{}}
}

func itrKey(ns, name string) string { return ns + "|" + name }

// ---- IdentityTokenRole methods (the ones this fake exists for) ----

func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cp := spec
	f.roles[itrKey(ns, name)] = &cp
	return nil
}

func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	r, ok := f.roles[itrKey(ns, name)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	delete(f.roles, itrKey(ns, name))
	return nil
}

// ---- minimal stubs for the rest of the Client surface ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) CheckAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) EnableAuthMount(ctx context.Context, mount, typ string, opts ...baoclient.CallOption) error {
	return nil
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
func (f *fakeBao) GetAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
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

func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, rn string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, rn string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, rn string, opts ...baoclient.CallOption) error {
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
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	return nil
}

// ---- harness ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoIdentityTokenRoleReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoIdentityTokenRole{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoIdentityTokenRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoIdentityTokenRoleFinalizer,
		Handlers:      OpenBaoIdentityTokenRoleHandlers(cl, fb),
	}
	return &OpenBaoIdentityTokenRoleReconciler{VaultResource: base}
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

func sampleRole() *v1alpha1.OpenBaoIdentityTokenRole {
	r := &v1alpha1.OpenBaoIdentityTokenRole{}
	r.Name = roleName
	r.Namespace = envtestNS
	r.Spec.Key = "platform"
	return r
}

func runReconcile(t *testing.T, r *OpenBaoIdentityTokenRoleReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getRole(t *testing.T, r *OpenBaoIdentityTokenRoleReconciler, ns, name string) *v1alpha1.OpenBaoIdentityTokenRole {
	t.Helper()
	var x v1alpha1.OpenBaoIdentityTokenRole
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: ns, Name: name}, &x))
	return &x
}

func readyCond(r *v1alpha1.OpenBaoIdentityTokenRole) *metav1.Condition {
	for i := range r.Status.Conditions {
		if r.Status.Conditions[i].Type == resource.ConditionReady {
			return &r.Status.Conditions[i]
		}
	}
	return nil
}

func TestOpenBaoITR_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	res := runReconcile(t, r, envtestNS, role.Name)

	require.Equal(t, 1, fb.writes)
	require.Equal(t, 5*time.Minute, res.RequeueAfter)
	cond := readyCond(getRole(t, r, envtestNS, role.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestOpenBaoITR_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)
	for i := 0; i < 3; i++ {
		runReconcile(t, r, envtestNS, role.Name)
	}
	require.Equal(t, 1, fb.writes,
		"steady-state reconciles must not re-write")
}

func TestOpenBaoITR_DriftPath_RewritesOnTTLChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	role.Spec.TTL = "3600s"
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)

	cur := getRole(t, r, envtestNS, role.Name)
	cur.Spec.TTL = "7200s"
	require.NoError(t, r.Update(context.Background(), cur))

	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 2, fb.writes)
	stored := fb.roles[itrKey("", roleName)]
	require.Equal(t, "7200s", stored.TTL)
}

func TestOpenBaoITR_SelfHealOnOOBDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)

	delete(fb.roles, itrKey("", roleName))
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 2, fb.writes)
}

func TestOpenBaoITR_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)

	cur := getRole(t, r, envtestNS, role.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.deletes)
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(),
			types.NamespacedName{Namespace: envtestNS, Name: role.Name},
			&v1alpha1.OpenBaoIdentityTokenRole{})))
}

func TestOpenBaoITR_RejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	role.Spec.Key = "" // rejected
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	res := runReconcile(t, r, envtestNS, role.Name)

	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getRole(t, r, envtestNS, role.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestOpenBaoITR_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	res := runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(getRole(t, r, envtestNS, role.Name))
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestOpenBaoITR_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleRole()
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleRole()
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)

	runReconcile(t, r, "ns-b", roleName)
	res := runReconcile(t, r, "ns-b", roleName)
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getRole(t, r, "ns-b", roleName))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)

	runReconcile(t, r, "ns-a", roleName)
	runReconcile(t, r, "ns-a", roleName)
	require.Equal(t, 1, fb.writes)
}

// Same name in different bao namespaces is not a collision.
func TestOpenBaoITR_NameCollision_DifferentBaoNamespace(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleRole()
	a.Namespace = "ns-a"
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := sampleRole()
	b.Namespace = "ns-b"
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildReconciler(t, fb, a, b)
	runReconcile(t, r, "ns-a", roleName)
	runReconcile(t, r, "ns-a", roleName)
	runReconcile(t, r, "ns-b", roleName)
	runReconcile(t, r, "ns-b", roleName)
	require.Equal(t, 2, fb.writes)
}

// Rename via spec.name cleans up the old bao identity.
func TestOpenBaoITR_RenameTracking(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Contains(t, fb.roles, itrKey("", roleName))

	cur := getRole(t, r, envtestNS, role.Name)
	cur.Spec.Name = "renamed"
	require.NoError(t, r.Update(context.Background(), cur))
	runReconcile(t, r, envtestNS, role.Name)

	require.NotContains(t, fb.roles, itrKey("", roleName))
	require.Contains(t, fb.roles, itrKey("", "renamed"))
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
