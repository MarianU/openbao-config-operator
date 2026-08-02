package openbaopkisecretengineconfig

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// keylessSetSignedBao models what OpenBao 2.6.1 actually does when
// intermediate/set-signed is called on a mount that has no pending private key
// (verified live: the call SUCCEEDS, imports the issuer with imported_keys=nil,
// and does NOT make it the mount's default issuer, so <mount>/cert/ca keeps
// answering 400 "no default issuer currently configured" — which the wrapper
// coalesces to baoclient.ErrNotFound).
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

	base := &resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPKISecretEngineConfigFinalizer,
		Handlers:      OpenBaoPKISecretEngineConfigHandlers(cl, scheme, bao),
	}
	return &OpenBaoPKISecretEngineConfigReconciler{VaultResource: base}
}

// TestIntermediateAfterStateLoss_ReportsActionableStatus covers an intermediate
// PKI config whose bao mount was recreated empty — a dev-mode restart, a
// restore-from-backup predating the CA, or a mount removed out of band. The
// mount comes back without its issuer, but the CR's CSR Secret lives in k8s and
// survives, and that Secret is what gates regeneration. So the flow replays the
// OLD CSR, whose private key bao no longer holds: set-signed reports success,
// binds nothing, and the readCASerial that follows finds no issuer.
//
// The CR wedges there. Status stays latched at phase=Active with a CA serial
// that no longer exists, and every ErrorBackoff retry imports another keyless
// issuer into the mount.
//
// This test does not fix the wedge — that still needs a human, and self-healing
// is tracked separately. What it pins is the diagnosis: the condition names the
// operation, the mount and the Secret to delete, instead of the bare
// "bao object not found" that made this take a live root-cause session to
// identify. Recovery by deleting that Secret is asserted at the end, and was
// confirmed against OpenBao 2.6.1 on-cluster.
//
// Tracked as M4 in the team's infra test plan, which is not in this repo.
func TestIntermediateAfterStateLoss_ReportsActionableStatus(t *testing.T) {
	t.Parallel()

	fb := &keylessSetSignedBao{fakeBao: newFakeBao()}
	// The signing root survived / was regenerated: sign-intermediate works.
	fb.caBySerial[key("", "pki-root")] = &baoclient.PKICAResponse{
		SerialNumber: "root-serial",
		Certificate:  "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
	}

	c := sampleIntermediateInternal()
	c.Finalizers = []string{OpenBaoPKISecretEngineConfigFinalizer}
	// Status latched from the CR's previous life, before bao lost state.
	c.Status.Phase = v1alpha1.PhaseActive
	c.Status.CASerialNumber = "stale-serial-from-before-state-loss"
	c.Status.Generated = true
	c.Status.Exported = true
	c.Status.Signed = true

	// The CSR Secret survived the bao-side state loss (it lives in k8s and is
	// owner-ref'd to the CR, which was not deleted).
	csrSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: c.Name + csrSecretSuffix, Namespace: envtestNS},
		Data:       map[string][]byte{csrSecretKey: []byte("STALE-CSR-FROM-DESTROYED-KEY")},
	}

	r := buildReconcilerWithClient(t, fb, c, csrSec)

	res := reconcile(t, r, c.Name)
	require.Equal(t, resource.ErrorBackoff, res.RequeueAfter,
		"stuck CR retries on the error backoff")

	got := getCfg(t, r, c.Name)
	cond := meta(got)
	require.NotNil(t, cond, "Ready condition must be set")

	// --- the status a human has to act on ---
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNotFound, cond.Reason,
		"a missing issuer is a not-found, not a generic BaoError — dashboards need to "+
			"separate it from a 500 or a network failure")
	require.Contains(t, cond.Message, "reading CA serial after set-signed",
		"message must name the operation that failed")
	require.Contains(t, cond.Message, c.Spec.Path,
		"message must name the mount")
	require.Contains(t, cond.Message, csrSecretName(c),
		"message must name the CSR Secret whose deletion is the recovery")
	require.NotEqual(t, "bao object not found", cond.Message,
		"the bare sentinel must never be the whole message again")

	// The CSR was never regenerated: the stale CSR is what got signed.
	require.Equal(t, 0, fb.genCSRs, "ensureCSRSecret reused the stored CSR")
	require.Equal(t, "STALE-CSR-FROM-DESTROYED-KEY", fb.lastSignCSR)

	// --- it does not self-heal, and each retry leaks an orphan issuer ---
	for i := 0; i < 3; i++ {
		reconcile(t, r, c.Name)
	}
	got = getCfg(t, r, c.Name)
	require.Contains(t, meta(got).Message, csrSecretName(c),
		"still stuck after 4 passes, and every pass repeats the recovery instruction")
	require.Equal(t, 4, fb.importedIssuers,
		"every ErrorBackoff retry imports another keyless issuer into the mount")

	// Status stays latched at Active while Ready=False — the CR advertises a CA
	// serial that no longer exists in bao.
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase)
	require.Equal(t, "stale-serial-from-before-state-loss", got.Status.CASerialNumber)

	// --- recovery: deleting ONLY the CSR Secret is enough (verified live) ---
	require.NoError(t, r.Delete(context.Background(), csrSec))
	reconcile(t, r, c.Name)
	// A fresh CSR is generated, so the fake's keyless model no longer applies;
	// assert the regeneration happened, which is the real gate.
	require.Equal(t, 1, fb.genCSRs,
		"with the CSR Secret gone the flow regenerates, creating a new pending key")
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
