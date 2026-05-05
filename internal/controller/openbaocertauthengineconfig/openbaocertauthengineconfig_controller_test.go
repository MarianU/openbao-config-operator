package openbaocertauthengineconfig

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
	mountP    = "cert"
)

type fakeBao struct {
	configs map[string]*baoclient.CertAuthConfigSpec // key: ns|mount

	writeErr error
	readErr  error

	writes, reads int
}

func newFakeBao() *fakeBao {
	return &fakeBao{configs: map[string]*baoclient.CertAuthConfigSpec{}}
}

func cfgKey(ns, mount string) string { return ns + "|" + mount }

func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, mount string, spec baoclient.CertAuthConfigSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cp := spec
	f.configs[cfgKey(ns, mount)] = &cp
	return nil
}

func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	cur, ok := f.configs[cfgKey(ns, mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *cur
	return &cp, nil
}

// rest of Client surface — stubs.
func (f *fakeBao) CheckKVv2Mount(ctx context.Context, m string, o ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) CheckAuthMount(ctx context.Context, m string, o ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) EnableAuthMount(ctx context.Context, m, t string, o ...baoclient.CallOption) error {
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
func (f *fakeBao) GetAuthMount(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.AuthMount, error) {
	return nil, baoclient.ErrNotFound
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
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, m, n string, s baoclient.JWTOIDCRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}

// ---- harness ----

func ptrInt(i int) *int { return &i }

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoCertAuthEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoCertAuthEngineConfig{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoCertAuthEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoCertAuthEngineConfigFinalizer,
		Handlers:      OpenBaoCertAuthEngineConfigHandlers(cl, fb),
	}
	return &OpenBaoCertAuthEngineConfigReconciler{VaultResource: base}
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

func sampleConfig() *v1alpha1.OpenBaoCertAuthEngineConfig {
	c := &v1alpha1.OpenBaoCertAuthEngineConfig{}
	c.Name = mountP
	c.Namespace = envtestNS
	c.Spec.Path = mountP
	c.Spec.OCSPCacheSize = ptrInt(200)
	return c
}

func runReconcile(t *testing.T, r *OpenBaoCertAuthEngineConfigReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getCfg(t *testing.T, r *OpenBaoCertAuthEngineConfigReconciler, ns, name string) *v1alpha1.OpenBaoCertAuthEngineConfig {
	t.Helper()
	var c v1alpha1.OpenBaoCertAuthEngineConfig
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &c))
	return &c
}

func readyCond(c *v1alpha1.OpenBaoCertAuthEngineConfig) *metav1.Condition {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == resource.ConditionReady {
			return &c.Status.Conditions[i]
		}
	}
	return nil
}

func TestCertAuthConfig_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, envtestNS, c.Name)
	res := runReconcile(t, r, envtestNS, c.Name)

	require.Equal(t, 1, fb.writes)
	require.Equal(t, 5*time.Minute, res.RequeueAfter)
	cond := readyCond(getCfg(t, r, envtestNS, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestCertAuthConfig_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, envtestNS, c.Name)
	runReconcile(t, r, envtestNS, c.Name)
	require.Equal(t, 1, fb.writes)
	for i := 0; i < 3; i++ {
		runReconcile(t, r, envtestNS, c.Name)
	}
	require.Equal(t, 1, fb.writes,
		"steady-state reconciles must not re-write")
}

// IsDeletable=false: CR delete releases finalizer without touching bao.
func TestCertAuthConfig_DeletePath_NoBaoCall(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, envtestNS, c.Name)
	runReconcile(t, r, envtestNS, c.Name)

	cur := getCfg(t, r, envtestNS, c.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, envtestNS, c.Name)

	// Bao state unchanged — config has no DELETE endpoint.
	require.Contains(t, fb.configs, cfgKey("", mountP))
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(),
			types.NamespacedName{Namespace: envtestNS, Name: c.Name},
			&v1alpha1.OpenBaoCertAuthEngineConfig{})),
		"CR should be removed from k8s")
}

func TestCertAuthConfig_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	c := sampleConfig()
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, envtestNS, c.Name)
	res := runReconcile(t, r, envtestNS, c.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(getCfg(t, r, envtestNS, c.Name))
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestCertAuthConfig_NameCollision(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleConfig()
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleConfig()
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)
	runReconcile(t, r, "ns-b", mountP)
	res := runReconcile(t, r, "ns-b", mountP)
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getCfg(t, r, "ns-b", mountP))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

func TestCertAuthConfig_RejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	c.Spec.Path = ""
	r := buildReconciler(t, fb, c)
	runReconcile(t, r, envtestNS, c.Name)
	res := runReconcile(t, r, envtestNS, c.Name)
	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getCfg(t, r, envtestNS, c.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}
