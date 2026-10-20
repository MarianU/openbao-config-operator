package openbaopkisecretengineconfig

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// Bao loses the private key behind an intermediate CA — a dev-mode restart, a
// restore predating the CA, or an unmount/remount, which a rename of the
// OpenBaoSecretEngine CR owning the path also does. The mount comes back empty
// while the CSR Secret survives in Kubernetes, and replaying that CSR is
// silently useless: sign and set-signed both succeed, and bao imports a
// certificate it holds no key for.
//
// Measured against OpenBao 2.6.1: an empty mount answers 404 on the keys
// listing, one with a pending or active key answers 200.

const staleCSR = "STALE-CSR-FROM-DESTROYED-KEY"

// keylessSetSignedBao models set-signed against a mount with no pending key.
// Verified live: the call SUCCEEDS, imports the issuer with imported_keys=nil,
// and does not make it the mount default, so <mount>/cert/ca keeps answering
// 400 "no default issuer currently configured".
//
// Reaching it now means detection was skipped or could not help, so tests use
// it to prove a path stops before set-signed.
type keylessSetSignedBao struct {
	*fakeBao
	// importedIssuers counts keyless issuers accumulated by repeated set-signed.
	importedIssuers int
}

func (k *keylessSetSignedBao) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	k.setSigneds++
	k.callOrder = append(k.callOrder, "set-signed")
	k.lastSetSigned = certificate
	k.importedIssuers++
	// No CA is registered: the imported issuer has no key, so it never becomes
	// the mount default. Deliberately does NOT populate caBySerial.
	return nil
}

// buildReconcilerWithClient mirrors buildReconciler but accepts any
// baoclient.Client so a behaviour override can be layered over fakeBao.
func buildReconcilerWithClient(t *testing.T, bao baoclient.Client, objs ...runtime.Object) *OpenBaoPKISecretEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoPKISecretEngineConfig{}).
		Build()

	rec := record.NewFakeRecorder(eventBuffer)
	base := &resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPKISecretEngineConfigFinalizer,
		Handlers:      OpenBaoPKISecretEngineConfigHandlers(cl, scheme, bao, rec),
		Recorder:      rec,
	}
	return &OpenBaoPKISecretEngineConfigReconciler{VaultResource: base}
}

// wedgedCSRSecret is the CSR Secret as it survives a bao-side state loss:
// present, owned by a live CR, holding a CSR whose key is gone.
func wedgedCSRSecret(crName string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: crName + csrSecretSuffix, Namespace: envtestNS},
		Data:       map[string][]byte{csrSecretKey: []byte(staleCSR)},
	}
}

// latchStateLoss stamps the status a CR carries into the wedge: Active before
// bao lost the key, and never cleared since.
func latchStateLoss(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
	c.Finalizers = []string{OpenBaoPKISecretEngineConfigFinalizer}
	c.Status.Phase = v1alpha1.PhaseActive
	c.Status.CASerialNumber = "stale-serial-from-before-state-loss"
	c.Status.Generated = true
	c.Status.Exported = true
	c.Status.Signed = true
}

// drainEvents returns everything the fake recorder buffered.
func drainEvents(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler) []string {
	t.Helper()
	fr, ok := r.Recorder.(*record.FakeRecorder)
	require.True(t, ok, "tests must build the reconciler with a FakeRecorder")
	var out []string
	for {
		select {
		case e := <-fr.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// rootCASurvives registers the signing root: these cases are about the
// intermediate's own key, not the root's.
func rootCASurvives(fb *fakeBao) {
	fb.caBySerial[key("", "pki-root")] = &baoclient.PKICAResponse{
		SerialNumber: "root-serial",
		Certificate:  "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
	}
}

// ---- internalSign: bao signs, so a lost key is recoverable without a human ----

// Nothing is waiting on the old key — bao signs this hierarchy itself — so the
// operator regenerates and converges in the same pass.
func TestIntermediateStateLoss_InternalSign_SelfHealsInOnePass(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)

	c := sampleIntermediateInternal()
	latchStateLoss(c)
	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name))

	res := reconcile(t, r, c.Name)
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter,
		"a healed CR is on the steady-state interval, not the error backoff")

	got := getCfg(t, r, c.Name)
	cond := meta(got)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status, "message was: %s", cond.Message)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase)
	require.Equal(t, "intermediate-serial", got.Status.CASerialNumber,
		"the CR must advertise the CA that now exists, not the one lost with the key")

	// Detected before signing: no wasted root signature, no keyless issuer.
	require.Equal(t, 1, fb.genCSRs, "regenerated exactly once")
	require.Equal(t, 1, fb.signs, "signed exactly once")
	require.Equal(t, 1, fb.setSigneds)
	require.NotEqual(t, staleCSR, fb.lastSignCSR, "the stale CSR must never reach the signer")

	// Overwritten in place — the Secret is never absent.
	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok, "the CSR Secret must still exist")
	require.NotEqual(t, staleCSR, string(sec.Data[csrSecretKey]))
}

// The base's Ready-transition Event says only that the object converged, which
// is indistinguishable from any other recovery.
func TestIntermediateStateLoss_InternalSign_EventNamesMountSerialAndConstraints(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)

	c := sampleIntermediateInternal()
	c.Spec.PermittedDnsDomains = []string{"team-a.svc", "team-a.pod"}
	latchStateLoss(c)
	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name))

	reconcile(t, r, c.Name)

	var regen string
	for _, e := range drainEvents(t, r) {
		if strings.Contains(e, reasonCARegenerated) {
			regen = e
			break
		}
	}
	require.NotEmpty(t, regen, "auto-regeneration must emit its own Event")
	require.Contains(t, regen, "Warning",
		"the CR ends up Ready, but a CA was silently replaced and leaf certs must be re-issued")
	require.Contains(t, regen, c.Spec.Path, "must name the mount")
	require.Contains(t, regen, "intermediate-serial", "must name the new CA serial")
	require.Contains(t, regen, "team-a.svc,team-a.pod",
		"the regenerated CA is built from the CR's current spec, so its name constraints "+
			"may differ from those of the CA it replaced")
}

// A first bring-up generates the CSR in this same pass, so its key is present
// by construction and there is nothing to probe.
func TestIntermediateFirstBringUp_InternalSign_DoesNotProbeForKeys(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)

	c := sampleIntermediateInternal()
	c.Finalizers = []string{OpenBaoPKISecretEngineConfigFinalizer}
	r := buildReconcilerWithClient(t, fb, c)

	reconcile(t, r, c.Name)

	require.Equal(t, metav1.ConditionTrue, meta(getCfg(t, r, c.Name)).Status)
	require.Equal(t, 1, fb.genCSRs)
	require.Zero(t, fb.listKeys,
		"a freshly generated CSR always matches its key; asking bao would be a wasted call")
}

// BaoWrite does not run once a CA is present, so the new read costs nothing on
// the every-5-minutes reconcile of a healthy fleet.
func TestIntermediateSteadyState_DoesNotProbeForKeys(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)

	c := sampleIntermediateInternal()
	c.Finalizers = []string{OpenBaoPKISecretEngineConfigFinalizer}
	r := buildReconcilerWithClient(t, fb, c)

	reconcile(t, r, c.Name) // bring up
	before := fb.listKeys
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)

	require.Equal(t, metav1.ConditionTrue, meta(getCfg(t, r, c.Name)).Status)
	require.Equal(t, before, fb.listKeys, "an Active intermediate must add no bao calls")
}

// Regeneration lands but the sign fails. The Secret now holds a CSR matching a
// real pending key, so the next pass skips detection and signs normally — no
// second regeneration, no new stuck state.
func TestIntermediateStateLoss_InternalSign_SignFailsAfterRegen_NextPassConverges(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)
	fb.signErr = &baoclient.StatusError{StatusCode: http.StatusServiceUnavailable}

	c := sampleIntermediateInternal()
	latchStateLoss(c)
	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name))

	reconcile(t, r, c.Name)
	require.Equal(t, metav1.ConditionFalse, meta(getCfg(t, r, c.Name)).Status)
	require.Equal(t, 1, fb.genCSRs)
	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok)
	regenerated := string(sec.Data[csrSecretKey])
	require.NotEqual(t, staleCSR, regenerated)

	fb.signErr = nil
	reconcile(t, r, c.Name)

	require.Equal(t, metav1.ConditionTrue, meta(getCfg(t, r, c.Name)).Status)
	require.Equal(t, 1, fb.genCSRs, "the second pass must reuse the regenerated CSR, not make another")
	require.Equal(t, regenerated, fb.lastSignCSR)
}

// A denied listing is not an empty mount. Reading it as one would re-key a
// healthy intermediate whose policy merely lost a grant.
func TestIntermediateStateLoss_ListKeysForbidden_DoesNotRegenerate(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	rootCASurvives(fb)
	fb.listKeysErr = &baoclient.StatusError{StatusCode: http.StatusForbidden}

	c := sampleIntermediateInternal()
	latchStateLoss(c)
	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name))

	res := reconcile(t, r, c.Name)
	require.Equal(t, resource.ErrorBackoff, res.RequeueAfter)

	cond := meta(getCfg(t, r, c.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason,
		"a policy gap must read as Forbidden, never as a missing key")
	require.Contains(t, cond.Message, "listing PKI keys")
	require.Zero(t, fb.genCSRs, "no CA material may be minted on an inconclusive read")
	require.Zero(t, fb.signs)
	require.Zero(t, fb.setSigneds)

	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok)
	require.Equal(t, staleCSR, string(sec.Data[csrSecretKey]), "the stored CSR must be untouched")
}

// The limitation, pinned. Detection cannot tell "any key" from "the key for
// this CSR", so a mount that lost its key and then had one generated out of
// band still wedges — and must still say which Secret to delete. Keeps
// readCASerial's not-found branch from being removed as unreachable.
func TestIntermediateStateLoss_KeyPresentButCSRMismatched_ReachesBackstop(t *testing.T) {
	t.Parallel()

	fb := &keylessSetSignedBao{fakeBao: newFakeBao()}
	rootCASurvives(fb.fakeBao)

	c := sampleIntermediateInternal()
	latchStateLoss(c)
	// A key exists on the mount, but not the one the stored CSR came from.
	fb.keysByMount[key("", c.Spec.Path)] = []string{"unrelated-key-generated-out-of-band"}

	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name))

	res := reconcile(t, r, c.Name)
	require.Equal(t, resource.ErrorBackoff, res.RequeueAfter)

	cond := meta(getCfg(t, r, c.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNotFound, cond.Reason)
	require.Contains(t, cond.Message, "reading CA serial after set-signed")
	require.Contains(t, cond.Message, csrSecretName(c),
		"the backstop must still name the Secret whose deletion is the recovery")
	require.Zero(t, fb.genCSRs, "detection passed, so the stale CSR was reused — that is the limitation")
	require.Equal(t, staleCSR, fb.lastSignCSR)
}

// ---- externalSignSecret: a human holds the other half, so never re-key ----

// The offline signature arrived, but the mount has no key to bind it to.
// Regenerating would invalidate the certificate someone just had signed, so the
// operator stops before set-signed and reports — leaking no issuer while it waits.
func TestIntermediateStateLoss_ExternalSign_ReportsAndNeverRegenerates(t *testing.T) {
	t.Parallel()

	fb := &keylessSetSignedBao{fakeBao: newFakeBao()}

	c := sampleIntermediateExternal("pki-ext", "signed-cert")
	latchStateLoss(c)
	signed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "signed-cert", Namespace: envtestNS},
		Data: map[string][]byte{
			defaultCertificateKey: []byte("-----BEGIN CERTIFICATE-----\nOFFLINE\n-----END CERTIFICATE-----\n"),
		},
	}
	r := buildReconcilerWithClient(t, fb, c, wedgedCSRSecret(c.Name), signed)

	res := reconcile(t, r, c.Name)
	require.Equal(t, resource.ErrorBackoff, res.RequeueAfter)

	cond := meta(getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNotFound, cond.Reason,
		"a mount with no key is a not-found, not a generic BaoError — dashboards need it "+
			"separable from a 500 or a network failure")
	require.Contains(t, cond.Message, c.Spec.Path, "must name the mount")
	require.Contains(t, cond.Message, csrSecretName(c), "must name the CSR Secret to delete")
	require.Contains(t, cond.Message, "signed-cert", "must name the Secret holding the offline signature")

	require.Zero(t, fb.genCSRs, "the offline signer's CSR must never be regenerated automatically")
	require.Zero(t, fb.setSigneds, "stopping before set-signed is what keeps the mount clean")
	require.Zero(t, fb.importedIssuers)

	// Repeated retries change nothing — no drift, no accumulation.
	for i := 0; i < 3; i++ {
		reconcile(t, r, c.Name)
	}
	require.Zero(t, fb.genCSRs)
	require.Zero(t, fb.importedIssuers,
		"the old behaviour imported one keyless issuer per ErrorBackoff retry, roughly 2,900 a day")

	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok)
	require.Equal(t, staleCSR, string(sec.Data[csrSecretKey]), "the stored CSR must be byte-identical")

	// Recovery is still a human deleting the CSR Secret, as documented.
	require.NoError(t, r.Delete(context.Background(), sec))
	reconcile(t, r, c.Name)
	require.Equal(t, 1, fb.genCSRs,
		"with the Secret gone the flow regenerates and waits for a new offline signature")
}

// Waiting passes return before anything depends on the stored CSR, so they cost
// nothing.
func TestIntermediateExternal_AwaitingSignature_DoesNotProbeForKeys(t *testing.T) {
	t.Parallel()

	fb := newFakeBao()
	c := sampleIntermediateExternal("pki-ext-wait", "signed-cert")
	c.Finalizers = []string{OpenBaoPKISecretEngineConfigFinalizer}
	r := buildReconcilerWithClient(t, fb, c)

	reconcile(t, r, c.Name) // pass 1: generate + store the CSR
	reconcile(t, r, c.Name) // pass 2: still waiting
	reconcile(t, r, c.Name) // pass 3: still waiting

	require.Equal(t, 1, fb.genCSRs, "R4 of the intermediate-CA plan: generated exactly once")
	require.Zero(t, fb.listKeys, "an awaiting CR must add no bao calls")
	require.Equal(t, resource.ReasonAwaitingExternalSignature, meta(getCfg(t, r, c.Name)).Reason)
}

// meta returns the Ready condition, or nil.
func meta(c *v1alpha1.OpenBaoPKISecretEngineConfig) *metav1.Condition {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == "Ready" {
			return &c.Status.Conditions[i]
		}
	}
	return nil
}
