package openbaojwtoidcauthengineconfig

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
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
	"github.com/stakater/openbao-config-operator/internal/hmacstore"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

func testHMAC() hmacstore.Computer {
	return hmacstore.NewComputerFromKey([]byte("test-hmac-key-stable-across-reconciles"))
}

const (
	envtestNS    = "default"
	mountP       = "oidc"
	clientSecret = "shhhh"
)

type fakeBao struct {
	configs           map[string]*baoclient.JWTOIDCConfigSpec
	writeErr, readErr error
	writes, reads     int
}

func newFakeBao() *fakeBao {
	return &fakeBao{configs: map[string]*baoclient.JWTOIDCConfigSpec{}}
}

func cfgKey(ns, m string) string { return ns + "|" + m }

func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, mount string, spec baoclient.JWTOIDCConfigSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := spec
	f.configs[cfgKey(baoclient.NamespaceFromOpts(opts), mount)] = &cp
	return nil
}

func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	cur, ok := f.configs[cfgKey(baoclient.NamespaceFromOpts(opts), mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *cur
	return &cp, nil
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
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, m string, s baoclient.K8sAuthConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
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
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, m, n string, s baoclient.JWTOIDCRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
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

// ---- harness ----

func buildReconciler(t *testing.T, fb baoclient.Client, objs ...runtime.Object) *OpenBaoJWTOIDCAuthEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoJWTOIDCAuthEngineConfigFinalizer,
		Handlers:      OpenBaoJWTOIDCAuthEngineConfigHandlers(cl, fb, testHMAC()),
		Recorder:      record.NewFakeRecorder(32),
	}
	return &OpenBaoJWTOIDCAuthEngineConfigReconciler{VaultResource: base, cl: cl}
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

func sampleSecret() *corev1.Secret {
	s := &corev1.Secret{}
	s.Name = "oidc-client"
	s.Namespace = envtestNS
	s.Data = map[string][]byte{"oidcClientSecret": []byte(clientSecret)}
	return s
}

func sampleConfig() *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig {
	c := &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}
	c.Name = mountP
	c.Namespace = envtestNS
	c.Spec.Path = mountP
	c.Spec.OIDCDiscoveryURL = "https://accounts.example.com"
	c.Spec.OIDCClientID = "bao-client"
	c.Spec.OIDCClientSecretRef = &v1alpha1.OIDCClientSecretRef{Name: "oidc-client"}
	return c
}

func runReconcile(t *testing.T, r *OpenBaoJWTOIDCAuthEngineConfigReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getCfg(t *testing.T, r *OpenBaoJWTOIDCAuthEngineConfigReconciler, name string) *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig {
	t.Helper()
	var c v1alpha1.OpenBaoJWTOIDCAuthEngineConfig
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &c))
	return &c
}

func readyCond(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) *metav1.Condition {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == resource.ConditionReady {
			return &c.Status.Conditions[i]
		}
	}
	return nil
}

func TestJWTOIDCConfig_CreatePath_ResolvesSecret(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	res := runReconcile(t, r, c.Name)

	require.Equal(t, 1, fb.writes)
	require.Equal(t, 5*time.Minute, res.RequeueAfter)
	stored := fb.configs[cfgKey("", mountP)]
	require.Equal(t, clientSecret, stored.OIDCClientSecret)

	cond := readyCond(getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestJWTOIDCConfig_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	c.Spec.OIDCClientSecretRef = nil // simplify the no-write-storm test
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes)
	for i := 0; i < 3; i++ {
		runReconcile(t, r, c.Name)
	}
	require.Equal(t, 1, fb.writes)
}

func TestJWTOIDCConfig_MissingSecret_RequeuesAsInternalError(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	r := buildReconciler(t, fb, c) // no secret

	runReconcile(t, r, c.Name)
	res := runReconcile(t, r, c.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getCfg(t, r, c.Name))
	require.Equal(t, resource.ReasonInternalError, cond.Reason)
}

// IsDeletable=false: CR delete releases finalizer without touching bao.
// Models real bao: oidc_client_secret is omitted from the read
// response (verified live earlier; openbao's pathConfigRead never
// includes it). The HMAC mechanism must still detect rotations.
type redactingFakeBao struct {
	*fakeBao
}

func (r *redactingFakeBao) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	cur, err := r.fakeBao.ReadJWTOIDCConfig(ctx, mount, opts...)
	if cur != nil {
		cp := *cur
		cp.OIDCClientSecret = "" // bao omits this on read
		return &cp, nil
	}
	return cur, err
}

// Definitive rotation test against a redaction-modeling fake — the
// case the previous "both non-empty" guard silently dropped.
func TestJWTOIDCConfig_SecretRotation_DetectedDespiteBaoRedaction(t *testing.T) {
	t.Parallel()
	fb := &redactingFakeBao{fakeBao: newFakeBao()}
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes, "initial create should write once")

	// Rotate the OIDC client_secret in-place.
	const rotated = "client-secret-v2-rotated"
	cur := &corev1.Secret{}
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: envtestNS, Name: "oidc-client"}, cur))
	cur.Data["oidcClientSecret"] = []byte(rotated)
	require.NoError(t, r.Update(context.Background(), cur))

	runReconcile(t, r, c.Name)
	require.Equal(t, 2, fb.writes,
		"rotation must trigger a re-write even though bao omits the client_secret on read")
	require.Equal(t, rotated, fb.fakeBao.configs[cfgKey("", mountP)].OIDCClientSecret)
}

func TestJWTOIDCConfig_DeletePath_NoBaoCall(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)

	cur := getCfg(t, r, c.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, c.Name)

	require.Contains(t, fb.configs, cfgKey("", mountP),
		"bao state must persist — config has no DELETE")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(),
			types.NamespacedName{Namespace: envtestNS, Name: c.Name},
			&v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{})))
}

func TestJWTOIDCConfig_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	res := runReconcile(t, r, c.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(getCfg(t, r, c.Name))
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}
