package openbaokubernetesauthengineconfig

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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/hmacstore"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

func testHMAC() hmacstore.Computer {
	return hmacstore.NewComputerFromKey([]byte("test-hmac-key-stable-across-reconciles"))
}

const (
	envtestNS = "default"
	mountP    = "kubernetes"
	apiHost   = "https://kubernetes.default.svc:443"
	tokJWT    = "eyJ.fake.jwt"
	rotJWT    = "eyJ.rotated.jwt"
	uidA      = "uid-a"
	uidB      = "uid-b"
)

type fakeBao struct {
	configs           map[string]*baoclient.K8sAuthConfigSpec
	writeErr, readErr error
	writes, reads     int
}

func newFakeBao() *fakeBao {
	return &fakeBao{configs: map[string]*baoclient.K8sAuthConfigSpec{}}
}

func cfgKey(ns, m string) string { return ns + "|" + m }

func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, mount string, spec baoclient.K8sAuthConfigSpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := spec
	f.configs[cfgKey(baoclient.NamespaceFromOpts(opts), mount)] = &cp
	return nil
}

func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
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

func buildReconciler(t *testing.T, fb baoclient.Client, objs ...runtime.Object) *OpenBaoKubernetesAuthEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoKubernetesAuthEngineConfig{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoKubernetesAuthEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoKubernetesAuthEngineConfigFinalizer,
		Handlers:      OpenBaoKubernetesAuthEngineConfigHandlers(cl, fb, testHMAC()),
	}
	return &OpenBaoKubernetesAuthEngineConfigReconciler{VaultResource: base, cl: cl}
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
	s.Name = "k8s-token"
	s.Namespace = envtestNS
	s.Data = map[string][]byte{"token": []byte(tokJWT)}
	return s
}

func sampleConfig() *v1alpha1.OpenBaoKubernetesAuthEngineConfig {
	c := &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}
	c.Name = mountP
	c.Namespace = envtestNS
	c.Spec.Path = mountP
	c.Spec.KubernetesHost = apiHost
	c.Spec.TokenReviewerJwtRef = &v1alpha1.KubernetesTokenReviewerSecretRef{Name: "k8s-token"}
	return c
}

func runReconcile(t *testing.T, r *OpenBaoKubernetesAuthEngineConfigReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getCfg(t *testing.T, r *OpenBaoKubernetesAuthEngineConfigReconciler, name string) *v1alpha1.OpenBaoKubernetesAuthEngineConfig {
	t.Helper()
	var c v1alpha1.OpenBaoKubernetesAuthEngineConfig
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &c))
	return &c
}

func readyCond(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) *metav1.Condition {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == resource.ConditionReady {
			return &c.Status.Conditions[i]
		}
	}
	return nil
}

func TestK8sAuthConfig_CreatePath_ResolvesSecret(t *testing.T) {
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
	require.Equal(t, tokJWT, stored.TokenReviewerJWT)
	require.Equal(t, apiHost, stored.KubernetesHost)

	cond := readyCond(getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestK8sAuthConfig_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	c.Spec.TokenReviewerJwtRef = nil
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes)
	for i := 0; i < 3; i++ {
		runReconcile(t, r, c.Name)
	}
	require.Equal(t, 1, fb.writes,
		"steady-state reconciles must not re-write")
}

func TestK8sAuthConfig_DriftCorrection(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	c.Spec.TokenReviewerJwtRef = nil
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes)

	// Out-of-band edit: bao now reports a different host.
	fb.configs[cfgKey("", mountP)].KubernetesHost = "https://other.example.com:6443"
	runReconcile(t, r, c.Name)
	require.Equal(t, 2, fb.writes, "drift must be re-written")
	require.Equal(t, apiHost, fb.configs[cfgKey("", mountP)].KubernetesHost)
}

// Secret rotation: rebuild status to clear the resolved value, then
// reconcile — the next pass picks up the new Secret value and writes
// it to bao.
func TestK8sAuthConfig_SecretRotationTriggersWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes)
	require.Equal(t, tokJWT, fb.configs[cfgKey("", mountP)].TokenReviewerJWT)

	// Rotate the secret on the apiserver.
	cur := &corev1.Secret{}
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: envtestNS, Name: "k8s-token"}, cur))
	cur.Data["token"] = []byte(rotJWT)
	require.NoError(t, r.Update(context.Background(), cur))

	runReconcile(t, r, c.Name)
	require.GreaterOrEqual(t, fb.writes, 2, "rotated secret must be re-written to bao")
	require.Equal(t, rotJWT, fb.configs[cfgKey("", mountP)].TokenReviewerJWT)
}

// Models real bao: the JWT field is redacted on read (always returns
// ""). Without the HMAC drift mechanism, the controller would never
// detect a Secret rotation; with it, rotation drives a re-write.
type redactingFakeBao struct {
	*fakeBao
}

func (r *redactingFakeBao) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	cur, err := r.fakeBao.ReadK8sAuthConfig(ctx, mount, opts...)
	if cur != nil {
		cp := *cur
		cp.TokenReviewerJWT = "" // bao redacts
		cp.KubernetesCACert = "" // bao redacts (the entire field, not just the body)
		return &cp, nil
	}
	return cur, err
}

// Definitive rotation test against a redaction-modeling fake. The
// previous "both non-empty" guard would have hidden the rotation here
// because cur.TokenReviewerJWT is always "". The HMAC mechanism
// detects the rotation regardless.
func TestK8sAuthConfig_SecretRotation_DetectedDespiteBaoRedaction(t *testing.T) {
	t.Parallel()
	fb := &redactingFakeBao{fakeBao: newFakeBao()}
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	runReconcile(t, r, c.Name)
	runReconcile(t, r, c.Name)
	require.Equal(t, 1, fb.writes, "initial create should write once")

	// Rotate the SA token Secret.
	cur := &corev1.Secret{}
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: envtestNS, Name: "k8s-token"}, cur))
	cur.Data["token"] = []byte(rotJWT)
	require.NoError(t, r.Update(context.Background(), cur))

	runReconcile(t, r, c.Name)
	require.Equal(t, 2, fb.writes,
		"rotation must trigger a re-write even though bao redacts the JWT on read")
	require.Equal(t, rotJWT, fb.fakeBao.configs[cfgKey("", mountP)].TokenReviewerJWT)
}

// IsDeletable=false: CR delete releases finalizer without touching bao.
func TestK8sAuthConfig_DeletePath_NoBaoCall(t *testing.T) {
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
			&v1alpha1.OpenBaoKubernetesAuthEngineConfig{})))
}

func TestK8sAuthConfig_BaoForbidden(t *testing.T) {
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

func TestK8sAuthConfig_MissingSecret_RequeuesAsInternalError(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig() // requires "k8s-token" Secret
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, c.Name)
	res := runReconcile(t, r, c.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getCfg(t, r, c.Name))
	require.Equal(t, resource.ReasonInternalError, cond.Reason)
}

func TestK8sAuthConfig_RejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	c.Spec.KubernetesHost = ""
	c.Spec.TokenReviewerJwtRef = nil
	r := buildReconciler(t, fb, c)

	runReconcile(t, r, c.Name)
	res := runReconcile(t, r, c.Name)
	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(getCfg(t, r, c.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestK8sAuthConfig_NameCollision(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleConfig()
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))
	older.Spec.TokenReviewerJwtRef = nil

	newer := sampleConfig()
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.TokenReviewerJwtRef = nil

	r := buildReconciler(t, fb, older, newer)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns-b", Name: mountP},
	})
	require.NoError(t, err)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns-b", Name: mountP},
	})
	require.NoError(t, err)
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	var loser v1alpha1.OpenBaoKubernetesAuthEngineConfig
	require.NoError(t, r.Get(context.Background(),
		types.NamespacedName{Namespace: "ns-b", Name: mountP}, &loser))
	cond := readyCond(&loser)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// Two CRs in different OpenBao namespaces don't collide — bao isolates
// by X-Vault-Namespace, so same mount path lives independently.
func TestK8sAuthConfig_DifferentOpenBaoNamespacesDoNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleConfig()
	a.Namespace = "ns-a"
	a.UID = uidA
	a.Spec.TokenReviewerJwtRef = nil
	a.Spec.OpenBaoNamespace = "team-a/"

	b := sampleConfig()
	b.Namespace = "ns-b"
	b.UID = uidB
	b.Spec.TokenReviewerJwtRef = nil
	b.Spec.OpenBaoNamespace = "team-b/"

	r := buildReconciler(t, fb, a, b)
	for _, ns := range []string{"ns-a", "ns-b"} {
		_, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: ns, Name: mountP},
		})
		require.NoError(t, err)
		_, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: ns, Name: mountP},
		})
		require.NoError(t, err)
	}
	require.Equal(t, 2, fb.writes)
	require.Contains(t, fb.configs, cfgKey("team-a/", mountP))
	require.Contains(t, fb.configs, cfgKey("team-b/", mountP))
}

// Watch handler maps a Secret event to all CRs that reference it.
func TestK8sAuthConfig_SecretWatchEnqueuesReferencingConfigs(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig()
	sec := sampleSecret()
	r := buildReconciler(t, fb, c, sec)

	reqs := r.configsReferencingSecret(context.Background(), sec)
	require.Len(t, reqs, 1)
	require.Equal(t, reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: c.Name},
	}, reqs[0])

	// Unrelated Secret enqueues nothing.
	other := &corev1.Secret{}
	other.Name = "unrelated"
	other.Namespace = envtestNS
	require.Empty(t, r.configsReferencingSecret(context.Background(), other))
}
