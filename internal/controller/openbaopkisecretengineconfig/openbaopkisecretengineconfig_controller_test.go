package openbaopkisecretengineconfig

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

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

const (
	envtestNS = "default"
	pkiPath   = "pki"
)

// fakeBao models PKI mount state in-memory. Only the four PKI methods
// the controller exercises (GenerateRootPKI, ReadPKICA, WritePKIURLs,
// ReadPKIURLs) carry behaviour. Everything else is a stub — the
// controller never touches them, but the type must satisfy the full
// baoclient.Client interface.
type fakeBao struct {
	caBySerial map[string]*baoclient.PKICAResponse // keyed "<openbaoNs>|<mount>"
	urls       map[string]*baoclient.PKIURLsInput  // same key
	nextSerial int

	generateErr error
	readCAErr   error
	writeURLErr error
	readURLErr  error

	generates, readCAs, writeURLs, readURLs int
}

func newFakeBao() *fakeBao {
	return &fakeBao{
		caBySerial: map[string]*baoclient.PKICAResponse{},
		urls:       map[string]*baoclient.PKIURLsInput{},
	}
}

func key(ns, mount string) string { return ns + "|" + mount }

// ---- PKI methods under test ----

func (f *fakeBao) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	f.generates++
	if f.generateErr != nil {
		return nil, f.generateErr
	}
	f.nextSerial++
	resp := &baoclient.PKICAResponse{
		SerialNumber: "fake-serial-" + string(rune('0'+f.nextSerial)),
		Certificate:  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
	}
	f.caBySerial[key(baoclient.NamespaceFromOpts(opts), mount)] = resp
	return resp, nil
}

func (f *fakeBao) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	f.readCAs++
	if f.readCAErr != nil {
		return nil, f.readCAErr
	}
	cur, ok := f.caBySerial[key(baoclient.NamespaceFromOpts(opts), mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return cur, nil
}

func (f *fakeBao) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	f.writeURLs++
	if f.writeURLErr != nil {
		return f.writeURLErr
	}
	cp := in
	f.urls[key(baoclient.NamespaceFromOpts(opts), mount)] = &cp
	return nil
}

func (f *fakeBao) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	f.readURLs++
	if f.readURLErr != nil {
		return nil, f.readURLErr
	}
	cur, ok := f.urls[key(baoclient.NamespaceFromOpts(opts), mount)]
	if !ok {
		return &baoclient.PKIURLsInput{}, nil
	}
	return cur, nil
}

// ---- stubs for the rest of baoclient.Client ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) CheckAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
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
func (f *fakeBao) EnableAuthMount(ctx context.Context, m, t string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMount(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.AuthMount, error) {
	return nil, baoclient.ErrNotFound
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
func (f *fakeBao) WritePKIRole(ctx context.Context, m, n string, s baoclient.PKIRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
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

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoPKISecretEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoPKISecretEngineConfig{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPKISecretEngineConfigFinalizer,
		Handlers:      OpenBaoPKISecretEngineConfigHandlers(cl, fb),
	}
	return &OpenBaoPKISecretEngineConfigReconciler{VaultResource: base}
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

func sampleConfig(name string) *v1alpha1.OpenBaoPKISecretEngineConfig {
	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Name = name
	c.Namespace = envtestNS
	c.Spec.Path = pkiPath
	c.Spec.PKIType = "root"
	c.Spec.CommonName = "Test CA"
	c.Spec.URLs = &v1alpha1.PKIURLs{
		IssuingCertificates: []string{"https://example.com/ca"},
	}
	return c
}

func reconcile(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getCfg(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler, name string) *v1alpha1.OpenBaoPKISecretEngineConfig {
	t.Helper()
	var c v1alpha1.OpenBaoPKISecretEngineConfig
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &c))
	return &c
}

// ---- tests ----

func TestPKIConfig_CreatePath_GeneratesCAAndWritesURLs(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // write

	require.Equal(t, 1, fb.generates, "first reconcile must generate CA")
	require.GreaterOrEqual(t, fb.writeURLs, 1, "URLs must be written")

	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase, "phase must be Active after generate")
	require.NotEmpty(t, got.Status.CASerialNumber, "serial must be captured from bao response")
}

// Destructive-overwrite guard: the second reconcile (or any later one)
// must NOT call GenerateRootPKI again. Calling it would overwrite the
// CA's private key and silently invalidate every cert ever issued by
// the previous CA. This is the most important invariant for PKIConfig.
func TestPKIConfig_DestructiveOverwriteGuard(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	// First create — generate fires once.
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	require.Equal(t, 1, fb.generates, "create path: generate runs once")

	// Multiple later reconciles — generate must NEVER fire again.
	for i := 0; i < 5; i++ {
		reconcile(t, r, c.Name)
	}
	require.Equal(t, 1, fb.generates,
		"DESTRUCTIVE OVERWRITE: GenerateRootPKI must not be called once a CA exists; would destroy private key")
}

// URL-only update: changing spec.urls drives a writeURLs call but
// leaves the CA untouched.
func TestPKIConfig_UpdatePath_URLsOnly(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	urlsAfterCreate := fb.writeURLs

	// Change URL spec, bump generation.
	cur := getCfg(t, r, c.Name)
	cur.Spec.URLs.IssuingCertificates = []string{"https://new.example.com/ca"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, c.Name)

	require.Equal(t, 1, fb.generates, "URL change must NOT regenerate the CA")
	require.Greater(t, fb.writeURLs, urlsAfterCreate, "URL change must propagate via WritePKIURLs")
}

// IsDeletable=false branch: deleting the CR releases the finalizer
// without calling BaoDelete (or any bao-side teardown). The CA stays
// in bao indefinitely.
func TestPKIConfig_DeletePath_IsDeletableFalse_PreservesCA(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	require.Equal(t, 1, fb.generates)
	caKey := key("", pkiPath)
	require.Contains(t, fb.caBySerial, caKey, "CA must exist before delete")

	// Now delete the CR.
	cur := getCfg(t, r, c.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, c.Name)

	// CR should be gone.
	var post v1alpha1.OpenBaoPKISecretEngineConfig
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: c.Name}, &post)
	require.Error(t, err, "CR must be deleted (finalizer released)")

	// Bao state must NOT be touched — IsDeletable=false guards the CA.
	require.Contains(t, fb.caBySerial, caKey,
		"IsDeletable=false: bao CA must survive CR delete; private key is irreplaceable")
}

// Collision: older creationTimestamp wins. Younger CR pointed at the
// same (path, openbaoNamespace) tuple goes Ready=False with reason
// NameCollision.
func TestPKIConfig_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleConfig("older")
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.Now()

	younger := sampleConfig("younger")
	younger.UID = "uid-younger"
	younger.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(1))

	r := buildReconciler(t, fb, older, younger)

	reconcile(t, r, older.Name)
	reconcile(t, r, older.Name)
	require.Equal(t, 1, fb.generates, "older must own the CA")

	reconcile(t, r, younger.Name)
	reconcile(t, r, younger.Name)
	require.Equal(t, 1, fb.generates,
		"younger CR must NOT regenerate; collision check guards the destructive call")

	cond := readyCond(t, getCfg(t, r, younger.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// Backfill in steady state: BaoWrite has run successfully, status
// shows Phase=Active and a serial. A subsequent reconcile (no spec
// drift, URLs match bao) must NOT call writeURLs again — that's
// busywork and surfaces as periodic write storms in audit logs.
func TestPKIConfig_SteadyState_DoesNotRewriteURLs(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // create CA + write URLs
	urlsAfterCreate := fb.writeURLs

	// Steady-state reconcile — no spec change, bao matches.
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)

	require.Equal(t, urlsAfterCreate, fb.writeURLs,
		"steady-state reconcile must NOT re-write URLs — bao state already matches")
}

// Backfill on status-incomplete CR: a CR with status.Phase blank
// (e.g. controller upgrade introduced new status fields, or a
// previous reconcile's status patch was rejected) must catch up to
// observed bao state on the next reconcile via the Backfill hook,
// even if no BaoWrite is needed.
func TestPKIConfig_BackfillStampsPhaseFromObservedState(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with a CA + matching URLs.
	fb.caBySerial[key("", pkiPath)] = &baoclient.PKICAResponse{SerialNumber: "stale-status-serial"}
	fb.urls[key("", pkiPath)] = &baoclient.PKIURLsInput{
		IssuingCertificates: []string{"https://example.com/ca"},
	}

	// CR with empty status — represents controller upgrade or earlier
	// failed status patch.
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // bao matches; no BaoWrite

	require.Equal(t, 0, fb.generates, "must not regenerate")
	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase,
		"Backfill hook must stamp Phase=Active when bao has a CA but status is empty")
	require.Equal(t, "stale-status-serial", got.Status.CASerialNumber,
		"Backfill must populate serial from observed bao state")
}

// Backfill on adoption: a CR pointed at an existing bao CA (created
// by an earlier CR or out of band) must end up with Phase=Active and
// CASerialNumber populated, even though BaoWrite doesn't generate.
// This relies on the PostWrite-mutator path: if the fakeBao's
// existing CA is observed, the mutator stamps phase/serial.
func TestPKIConfig_AdoptsExistingCA_PopulatesPhaseAndSerial(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with a CA the controller didn't create.
	preexisting := &baoclient.PKICAResponse{SerialNumber: "out-of-band-serial", Certificate: "PEM"}
	fb.caBySerial[key("", pkiPath)] = preexisting

	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // write — adopts existing CA

	got := getCfg(t, r, c.Name)
	require.Equal(t, 0, fb.generates,
		"existing CA must NOT be regenerated (destructive overwrite guard)")
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase,
		"adopting an existing CA must still flip phase to Active via the StatusMutator")
	require.Equal(t, "out-of-band-serial", got.Status.CASerialNumber,
		"serial of the adopted CA must be captured via the StatusMutator")
}

func readyCond(t *testing.T, c *v1alpha1.OpenBaoPKISecretEngineConfig) *metav1.Condition {
	t.Helper()
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == resource.ConditionReady {
			return &c.Status.Conditions[i]
		}
	}
	return nil
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
