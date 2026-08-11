package openbaogroupalias

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

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

const (
	envtestNS  = "default"
	mountAuth  = "auth_oidc_abc"
	uidA       = "uid-a"
	uidB       = "uid-b"
	parentName = "team-a"
	parentID   = "g-100"
)

// fakeBao stores aliases keyed by id. Lookups by (mount, name) walk the
// map — mirrors bao's id-keyed storage with a list-by-mount index.
type fakeBao struct {
	aliases map[string]*baoclient.IdentityGroupAlias
	nextID  int

	writeErr  error
	readErr   error
	deleteErr error

	writes, reads, deletes, finds int
}

func newFakeBao() *fakeBao {
	return &fakeBao{aliases: map[string]*baoclient.IdentityGroupAlias{}}
}

// ---- baoclient.Client surface — relevant identity methods, stubs for the rest ----

func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, spec baoclient.IdentityGroupAliasSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	f.writes++
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	id := spec.ID
	if id == "" {
		f.nextID++
		id = "ga-" + iToA(f.nextID)
	}
	g := &baoclient.IdentityGroupAlias{
		ID:            id,
		Name:          spec.Name,
		MountAccessor: spec.MountAccessor,
		CanonicalID:   spec.CanonicalID,
	}
	f.aliases[id] = g
	return &baoclient.IdentityGroupAlias{
		ID:            g.ID,
		Name:          g.Name,
		MountAccessor: g.MountAccessor,
		CanonicalID:   g.CanonicalID,
	}, nil
}

func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	g, ok := f.aliases[id]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return &baoclient.IdentityGroupAlias{
		ID:            g.ID,
		Name:          g.Name,
		MountAccessor: g.MountAccessor,
		CanonicalID:   g.CanonicalID,
	}, nil
}

func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, mount string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	f.finds++
	for _, g := range f.aliases {
		if g.Name == name && g.MountAccessor == mount {
			return &baoclient.IdentityGroupAlias{
				ID:            g.ID,
				Name:          g.Name,
				MountAccessor: g.MountAccessor,
				CanonicalID:   g.CanonicalID,
			}, nil
		}
	}
	return nil, baoclient.ErrNotFound
}

func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.aliases, id)
	return nil
}

// rest of Client surface — stubs.
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
func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
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
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

func iToA(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = digits[i%10]
		i /= 10
	}
	return string(buf[pos:])
}

// ---- harness ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoGroupAliasReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoGroupAlias{}, &v1alpha1.OpenBaoGroup{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoGroupAlias]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoGroupAliasFinalizer,
		Handlers:      OpenBaoGroupAliasHandlers(cl, fb),
	}
	return &OpenBaoGroupAliasReconciler{VaultResource: base, cl: cl}
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

func sampleParentGroup() *v1alpha1.OpenBaoGroup {
	g := &v1alpha1.OpenBaoGroup{}
	g.Name = parentName
	g.Namespace = envtestNS
	g.Spec.Type = v1alpha1.GroupTypeExternal
	g.Status.GroupID = parentID
	return g
}

// aliasName is the canonical CR/spec name used by every fixture in
// this file. Extracted to satisfy unparam (single-value parameter)
// while keeping the construction helper readable.
const aliasName = "alice"

func sampleAlias() *v1alpha1.OpenBaoGroupAlias {
	a := &v1alpha1.OpenBaoGroupAlias{}
	a.Name = aliasName
	a.Namespace = envtestNS
	a.Spec.Name = aliasName
	a.Spec.MountAccessor = mountAuth
	a.Spec.CanonicalGroupRef = &v1alpha1.OpenBaoGroupRef{Name: parentName}
	return a
}

func runReconcile(t *testing.T, r *OpenBaoGroupAliasReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getAlias(t *testing.T, r *OpenBaoGroupAliasReconciler, ns, name string) *v1alpha1.OpenBaoGroupAlias {
	t.Helper()
	var a v1alpha1.OpenBaoGroupAlias
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &a))
	return &a
}

func readyCond(t *testing.T, a *v1alpha1.OpenBaoGroupAlias) *metav1.Condition {
	t.Helper()
	for i := range a.Status.Conditions {
		if a.Status.Conditions[i].Type == resource.ConditionReady {
			return &a.Status.Conditions[i]
		}
	}
	return nil
}

// ---- create / drift / delete ----

func TestOpenBaoGroupAlias_CreatePath_StampsAliasIDAndCanonicalID(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	res := runReconcile(t, r, envtestNS, a.Name)
	require.Equal(t, 1, fb.writes)
	require.Equal(t, 5*time.Minute, res.RequeueAfter)

	got := getAlias(t, r, envtestNS, a.Name)
	require.NotEmpty(t, got.Status.AliasID)
	require.Equal(t, parentID, got.Status.ResolvedCanonicalID)
	cond := readyCond(t, got)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

// Without a parent group the controller surfaces ReasonInternalError
// and requeues — the alias must not be written with empty canonical_id.
func TestOpenBaoGroupAlias_ParentNotReady_Requeues(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	parent := &v1alpha1.OpenBaoGroup{}
	parent.Name = parentName
	parent.Namespace = envtestNS
	// status.GroupID empty

	a := sampleAlias()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	res := runReconcile(t, r, envtestNS, a.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	require.Equal(t, 0, fb.writes, "must not write alias when parent has no GroupID")
	cond := readyCond(t, getAlias(t, r, envtestNS, a.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason)
}

// Drift: parent group's canonical id rotates → alias must re-resolve
// and re-write.
func TestOpenBaoGroupAlias_Drift_OnParentIDRotation(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	parent := sampleParentGroup()
	a := sampleAlias()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	runReconcile(t, r, envtestNS, a.Name)
	require.Equal(t, 1, fb.writes)
	got := getAlias(t, r, envtestNS, a.Name)
	require.Equal(t, parentID, got.Status.ResolvedCanonicalID)

	// Parent rotates id (group recreated with same name).
	freshParent := getParentGroup(t, r)
	freshParent.Status.GroupID = "g-rotated"
	require.NoError(t, r.Status().Update(context.Background(), freshParent))

	runReconcile(t, r, envtestNS, a.Name)

	require.Equal(t, 2, fb.writes,
		"alias must re-write when parent GroupID rotates")
	got = getAlias(t, r, envtestNS, a.Name)
	require.Equal(t, "g-rotated", got.Status.ResolvedCanonicalID)
}

func getParentGroup(t *testing.T, r *OpenBaoGroupAliasReconciler) *v1alpha1.OpenBaoGroup {
	t.Helper()
	var g v1alpha1.OpenBaoGroup
	require.NoError(t, r.cl.Get(context.Background(),
		types.NamespacedName{Namespace: envtestNS, Name: parentName}, &g))
	return &g
}

// OOB delete heals on next reconcile. With status.AliasID stamped, the
// BaoGet reads by id and returns ErrNotFound; the controller falls
// through to BaoWrite.
func TestOpenBaoGroupAlias_SelfHealOnOOBDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	runReconcile(t, r, envtestNS, a.Name)
	require.Equal(t, 1, fb.writes)
	got := getAlias(t, r, envtestNS, a.Name)
	stampedID := got.Status.AliasID
	require.NotEmpty(t, stampedID)

	delete(fb.aliases, stampedID)
	runReconcile(t, r, envtestNS, a.Name)

	require.Equal(t, 2, fb.writes,
		"OOB delete must trigger re-create on next reconcile")
}

// status.AliasID stays stable across reconciles when state matches.
func TestOpenBaoGroupAlias_NoWriteStorm(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	runReconcile(t, r, envtestNS, a.Name)
	require.Equal(t, 1, fb.writes)

	for i := 0; i < 3; i++ {
		runReconcile(t, r, envtestNS, a.Name)
	}
	require.Equal(t, 1, fb.writes,
		"steady-state reconciles must not re-write")
}

func TestOpenBaoGroupAlias_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	runReconcile(t, r, envtestNS, a.Name)
	require.Equal(t, 1, fb.writes)

	cur := getAlias(t, r, envtestNS, a.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	runReconcile(t, r, envtestNS, a.Name)

	require.Equal(t, 1, fb.deletes)
	require.Empty(t, fb.aliases)
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: a.Name},
			&v1alpha1.OpenBaoGroupAlias{})))
}

// Backfill: a fresh CR with no status (re-applied from manifest) finds
// its existing alias by (mount, name) and stamps status.AliasID.
func TestOpenBaoGroupAlias_Backfill_FindsExistingAlias(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with an alias matching what the CR will write.
	fb.aliases["ga-prebuilt"] = &baoclient.IdentityGroupAlias{
		ID:            "ga-prebuilt",
		Name:          "alice",
		MountAccessor: mountAuth,
		CanonicalID:   parentID,
	}
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	runReconcile(t, r, envtestNS, a.Name)

	got := getAlias(t, r, envtestNS, a.Name)
	require.Equal(t, "ga-prebuilt", got.Status.AliasID,
		"Backfill must stamp the discovered alias id")
	require.Equal(t, 0, fb.writes, "matching state must not trigger a write")
}

// 403 from bao surfaces as Reason=Forbidden.
func TestOpenBaoGroupAlias_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	a := sampleAlias()
	parent := sampleParentGroup()
	r := buildReconciler(t, fb, parent, a)

	runReconcile(t, r, envtestNS, a.Name)
	res := runReconcile(t, r, envtestNS, a.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getAlias(t, r, envtestNS, a.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestOpenBaoGroupAlias_RejectsInvalid(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleAlias()
	a.Spec.CanonicalGroupRef = nil // neither canonicalId nor groupRef
	a.Spec.CanonicalID = ""
	r := buildReconciler(t, fb, a)

	runReconcile(t, r, envtestNS, a.Name)
	res := runReconcile(t, r, envtestNS, a.Name)

	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(t, getAlias(t, r, envtestNS, a.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

// C2: same (mount, name, ns) tuple from two CRs → older wins.
func TestOpenBaoGroupAlias_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	parent := sampleParentGroup()

	older := sampleAlias()
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleAlias()
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.CanonicalGroupRef.Namespace = envtestNS

	r := buildReconciler(t, fb, parent, older, newer)
	older.Spec.CanonicalGroupRef.Namespace = envtestNS
	require.NoError(t, r.cl.Update(context.Background(), older))

	runReconcile(t, r, "ns-b", "alice")
	res := runReconcile(t, r, "ns-b", "alice")
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(t, getAlias(t, r, "ns-b", "alice"))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)

	// Older proceeds.
	runReconcile(t, r, "ns-a", "alice")
	runReconcile(t, r, "ns-a", "alice")
	require.Equal(t, 1, fb.writes)
}

// Different mount accessors → not a collision (bao stores them as
// distinct aliases).
func TestOpenBaoGroupAlias_NameCollision_DifferentMountIsNotACollision(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	parent := sampleParentGroup()

	a := sampleAlias()
	a.Namespace = "ns-a"
	a.UID = uidA
	a.Spec.CanonicalGroupRef.Namespace = envtestNS

	b := sampleAlias()
	b.Namespace = "ns-b"
	b.UID = uidB
	b.Spec.MountAccessor = "auth_jwt_xyz"
	b.Spec.CanonicalGroupRef.Namespace = envtestNS

	r := buildReconciler(t, fb, parent, a, b)

	runReconcile(t, r, "ns-a", "alice")
	runReconcile(t, r, "ns-a", "alice")
	runReconcile(t, r, "ns-b", "alice")
	runReconcile(t, r, "ns-b", "alice")

	require.Equal(t, 2, fb.writes,
		"same alias name on different mounts must not collide")
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
