package openbaojwtoidcauthenginerole

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

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

const (
	envtestNS = "default"
	uidA      = "uid-a"
	uidB      = "uid-b"
	mountP    = "oidc"
	roleName  = "tenant"
)

type fakeBao struct {
	roles map[string]*baoclient.JWTOIDCRoleSpec

	writeErr, readErr, deleteErr error
	writes, reads, deletes       int
}

func newFakeBao() *fakeBao {
	return &fakeBao{roles: map[string]*baoclient.JWTOIDCRoleSpec{}}
}

func roleKey(ns, m, n string) string { return ns + "|" + m + "|" + n }

func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := spec
	f.roles[roleKey(baoclient.NamespaceFromOpts(opts), mount, name)] = &cp
	return nil
}

func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	cur, ok := f.roles[roleKey(baoclient.NamespaceFromOpts(opts), mount, name)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *cur
	return &cp, nil
}

func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.roles, roleKey(baoclient.NamespaceFromOpts(opts), mount, name))
	return nil
}

// stubs for the rest of the Client interface
func (f *fakeBao) CheckKVv2Mount(ctx context.Context, m string, o ...baoclient.CallOption) (bool, error) {
	return true, nil
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
func (f *fakeBao) EnableAuthMethod(ctx context.Context, m string, s baoclient.AuthMethodMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneAuthMethod(ctx context.Context, m string, s baoclient.AuthMethodMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMethod(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) UpsertPolicy(ctx context.Context, n, r string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, n string, o ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, n string, o ...baoclient.CallOption) error {
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
func (f *fakeBao) WritePKIRole(ctx context.Context, m, n string, s baoclient.PKIRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroup(ctx context.Context, s baoclient.IdentityGroupSpec, o ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroup(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, s baoclient.IdentityGroupAliasSpec, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, n, ma string, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, n string, s baoclient.IdentityTokenRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, m string, s baoclient.CertAuthConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteCertAuthRole(ctx context.Context, m, n string, s baoclient.CertAuthRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteCertAuthRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, m string, s baoclient.JWTOIDCConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, m string, s baoclient.K8sAuthConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteTransitKey(ctx context.Context, m, n string, s baoclient.TransitKeySpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadTransitKey(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) UpdateTransitKeyConfig(ctx context.Context, m, n string, s baoclient.TransitKeySpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DeleteTransitKey(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoJWTOIDCAuthEngineRoleReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoJWTOIDCAuthEngineRoleFinalizer,
		Handlers:      OpenBaoJWTOIDCAuthEngineRoleHandlers(cl, fb),
	}
	return &OpenBaoJWTOIDCAuthEngineRoleReconciler{VaultResource: base}
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

func sampleRole() *v1alpha1.OpenBaoJWTOIDCAuthEngineRole {
	r := &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}
	r.Name = roleName
	r.Namespace = envtestNS
	r.Spec.Path = mountP
	r.Spec.RoleType = v1alpha1.JWTOIDCRoleTypeOIDC
	r.Spec.UserClaim = "email"
	r.Spec.AllowedRedirectURIs = []string{"https://bao.example.com/ui/vault/auth/oidc/oidc/callback"}
	r.Spec.TokenPolicies = []string{"tenant"}
	return r
}

func runReconcile(t *testing.T, r *OpenBaoJWTOIDCAuthEngineRoleReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getRole(t *testing.T, r *OpenBaoJWTOIDCAuthEngineRoleReconciler, ns, name string) *v1alpha1.OpenBaoJWTOIDCAuthEngineRole {
	t.Helper()
	var role v1alpha1.OpenBaoJWTOIDCAuthEngineRole
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: ns, Name: name}, &role))
	return &role
}

func readyCond(role *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) *metav1.Condition {
	for i := range role.Status.Conditions {
		if role.Status.Conditions[i].Type == resource.ConditionReady {
			return &role.Status.Conditions[i]
		}
	}
	return nil
}

func TestJWTOIDCRole_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	res := runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)
	require.Equal(t, 5*time.Minute, res.RequeueAfter)

	got := getRole(t, r, envtestNS, role.Name)
	require.Equal(t, mountP, got.Status.LastWrittenPath)
}

func TestJWTOIDCRole_NoWriteStorm(t *testing.T) {
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
	require.Equal(t, 1, fb.writes)
}

func TestJWTOIDCRole_DeletePath(t *testing.T) {
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
			&v1alpha1.OpenBaoJWTOIDCAuthEngineRole{})))
}

func TestJWTOIDCRole_SelfHealOnOOBDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	r := buildReconciler(t, fb, role)

	runReconcile(t, r, envtestNS, role.Name)
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 1, fb.writes)

	delete(fb.roles, roleKey("", mountP, roleName))
	runReconcile(t, r, envtestNS, role.Name)
	require.Equal(t, 2, fb.writes)
}

func TestJWTOIDCRole_BaoForbidden(t *testing.T) {
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

func TestJWTOIDCRole_RejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	role := sampleRole()
	role.Spec.UserClaim = "" // rejected
	r := buildReconciler(t, fb, role)
	runReconcile(t, r, envtestNS, role.Name)
	res := runReconcile(t, r, envtestNS, role.Name)
	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getRole(t, r, envtestNS, role.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestJWTOIDCRole_NameCollision(t *testing.T) {
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
}
