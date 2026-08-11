package openbaopkisecretengineconfig

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update

// OpenBaoPKISecretEngineConfigFinalizer follows the Kubernetes
// convention <resource>.<group>/finalizer.
const OpenBaoPKISecretEngineConfigFinalizer = "openbaopkisecretengineconfig.security.mto.stakater.com/finalizer"

// csrSecretSuffix is appended to the CR name to form the CSR Secret's name.
const csrSecretSuffix = "-intermediate-csr"

// csrSecretKey is the data key under which the intermediate CSR is stored.
const csrSecretKey = "csr"

// defaultCertificateKey is the externalSignSecret data key read when
// spec.certificateKey is empty (matches the CRD default).
const defaultCertificateKey = "tls.crt"

// reasonCARegenerated is the Event reason for an auto-healed intermediate CA.
const reasonCARegenerated = "IntermediateCARegenerated"

// caBundleKey is the ConfigMap data key the published CA cert PEM is written
// under (the conventional trust-bundle key cert-manager trust-manager sources).
const caBundleKey = "ca.crt"

type OpenBaoPKISecretEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]
}

// NewOpenBaoPKISecretEngineConfigReconcilerWithClient is the
// test-friendly constructor.
func NewOpenBaoPKISecretEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoPKISecretEngineConfigReconciler {
	return &OpenBaoPKISecretEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoPKISecretEngineConfig](
			mgr, OpenBaoPKISecretEngineConfigFinalizer,
			OpenBaoPKISecretEngineConfigHandlers(mgr.GetClient(), mgr.GetScheme(), bao,
				resource.EventRecorderFor(mgr))),
	}
}

// OpenBaoPKISecretEngineConfigHandlers builds the bao-I/O callbacks.
//
// BaoGet probes for an existing CA and reads URL config in one payload. The
// boolean caExists is the BaoWrite gate: a present CA must NEVER be regenerated
// (would destroy the private key), so BaoWrite only generates/signs when no CA
// is present. This holds for both type=root and type=intermediate — an
// intermediate's CA only appears after set-signed, so until then ReadPKICA
// returns ErrNotFound and the create/sign path keeps running.
//
// rec reports what the base's Ready-transition Event cannot: that a CA was
// regenerated rather than merely recovered. Optional; nil skips the Event.
func OpenBaoPKISecretEngineConfigHandlers(cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, rec record.EventRecorder) resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoPKISecretEngineConfig {
			return &v1alpha1.OpenBaoPKISecretEngineConfig{}
		},

		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) (map[string]any, error) {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			ca, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
			var caSerial, caCert string
			switch {
			case err == nil && ca != nil:
				caSerial = ca.SerialNumber
				caCert = ca.Certificate
			case errors.Is(err, baoclient.ErrNotFound):
				// CA absent → tell the base "needs create".
				return nil, resource.ErrBaoNotFound
			default:
				if err != nil {
					return nil, err
				}
			}
			urls, err := bao.ReadPKIURLs(ctx, p.Spec.Path, ns)
			if err != nil {
				return nil, err
			}
			urlsMap := map[string][]string{
				"issuingCertificates":   nil,
				"crlDistributionPoints": nil,
				"ocspServers":           nil,
			}
			if urls != nil {
				urlsMap["issuingCertificates"] = urls.IssuingCertificates
				urlsMap["crlDistributionPoints"] = urls.CRLDistributionPoints
				urlsMap["ocspServers"] = urls.OCSPServers
			}
			payload := map[string]any{
				"caExists": true,
				"caSerial": caSerial,
				"caCert":   caCert,
				"urls":     urlsMap,
			}
			// Surface the published CA-bundle ConfigMap's current content so
			// the drift check (IsEquivalentToDesiredState) republishes when it
			// is missing/stale/deleted.
			if name := strings.TrimSpace(p.Spec.PublishCABundleConfigMap); name != "" {
				published, err := readPublishedCABundle(ctx, cl, p.Namespace, name)
				if err != nil {
					return nil, err
				}
				payload["publishedCABundle"] = published
			}
			return payload, nil
		},

		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig], error) {
			if err := checkPKIConfigCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())

			// Re-probe inside BaoWrite so a concurrent reconcile that raced
			// past us doesn't get its CA overwritten. A present CA is final
			// for both root and intermediate — regenerating destroys the
			// private key.
			existing, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
			switch {
			case err == nil && existing != nil:
				return finishActive(ctx, cl, scheme, bao, p, ns, existing.SerialNumber, false)
			case errors.Is(err, baoclient.ErrNotFound):
				// No CA yet — create per type below.
			default:
				return nil, err
			}

			switch p.PKIType() {
			case v1alpha1.PKITypeRoot:
				// Raise this mount's max_lease_ttl to cover spec.TTL before
				// generating: bao caps a generated CA cert to the mount's
				// max_lease_ttl (default 768h), so a long-lived root (e.g.
				// spec.TTL=175200h) would otherwise be issued for only ~32
				// days. An intermediate's cert is instead bounded by its
				// signing root mount (see baoWriteIntermediateInternal), so
				// the tune only applies on the root path.
				if err := ensureMountMaxLeaseTTL(ctx, bao, p, ns); err != nil {
					return nil, err
				}
				resp, err := generateRoot(ctx, bao, p, ns)
				if err != nil {
					return nil, err
				}
				var serial string
				if resp != nil {
					serial = resp.SerialNumber
				}
				return finishActive(ctx, cl, scheme, bao, p, ns, serial, false)
			case v1alpha1.PKITypeIntermediate:
				if hasInternalSign(p) {
					return baoWriteIntermediateInternal(ctx, cl, scheme, bao, rec, p, ns)
				}
				return baoWriteIntermediateExternal(ctx, cl, scheme, bao, p, ns)
			default:
				// IsValid already rejects this; defensive guard so an
				// unhandled type fails loudly rather than silently no-ops.
				return nil, fmt.Errorf("%w: unsupported spec.type %q", resource.ErrInvalidSpec, p.Spec.Type)
			}
		},

		Backfill: func(p *v1alpha1.OpenBaoPKISecretEngineConfig, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig] {
			// Steady-state path: bao matches desired, BaoWrite did not run, but
			// the CR's status may lack Phase/CASerialNumber (earlier transient
			// patch failure, or adoption of a CA a previous controller version
			// created without stamping status).
			if p.Status.Phase == v1alpha1.PhaseActive && p.Status.CASerialNumber != "" {
				return nil
			}
			serial, _ := current["caSerial"].(string)
			if serial == "" {
				return nil
			}
			return func(cur *v1alpha1.OpenBaoPKISecretEngineConfig) {
				cur.MarkActive(serial)
			}
		},

		BaoDelete: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) error {
			// Never reached (IsDeletable=false). Fails loudly so a future
			// IsDeletable flip cannot silently release the finalizer —
			// disabling the mount is the only "delete CA" surface and it
			// destroys the private key.
			return fmt.Errorf("%w: BaoDelete invoked for OpenBaoPKISecretEngineConfig %q — "+
				"IsDeletable=false must keep the delete path away from bao",
				resource.ErrInternal, p.BaoName())
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoPKISecretEngineConfig, name, _ string) error {
			// Never reached: renames orphan when IsDeletable=false. Fails
			// loudly for the same reason as BaoDelete.
			return fmt.Errorf("%w: BaoDeleteIdentity invoked for PKI mount %q — "+
				"IsDeletable=false must keep rename cleanup away from bao",
				resource.ErrInternal, name)
		},

		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) error {
			return checkPKIConfigCollision(ctx, cl, p)
		},
	}
}

// hasInternalSign reports whether the CR selects the in-bao signing model.
func hasInternalSign(p *v1alpha1.OpenBaoPKISecretEngineConfig) bool {
	return p.Spec.InternalSign != nil && strings.TrimSpace(p.Spec.InternalSign.Name) != ""
}

// finishActive writes the URL config (skipping the round-trip when it already
// matches), publishes the CA-bundle ConfigMap when requested, and returns the
// status mutator that flips Phase=Active + CASerialNumber. When markIntermediate
// is true the mutator also stamps the upstream bootstrap booleans
// generated/exported/signed.
func finishActive(ctx context.Context, cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption, serial string, markIntermediate bool) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig], error) {
	currentURLs, err := bao.ReadPKIURLs(ctx, p.Spec.Path, ns)
	if err != nil {
		return nil, err
	}
	if !urlsEqual(currentURLs, p) {
		if err := writeURLs(ctx, bao, p, ns); err != nil {
			return nil, err
		}
	}
	if err := publishCABundle(ctx, cl, scheme, bao, p, ns); err != nil {
		return nil, err
	}
	return func(cur *v1alpha1.OpenBaoPKISecretEngineConfig) {
		cur.MarkActive(serial)
		if markIntermediate {
			cur.Status.Generated = true
			cur.Status.Exported = true
			cur.Status.Signed = true
		}
	}, nil
}

// publishCABundle keeps spec.publishCABundleConfigMap populated with the active
// CA cert PEM (key "ca.crt") for trust-distribution tooling. No-op when the
// field is empty. Idempotent: writes only when the ConfigMap is missing or its
// content differs from the active CA. Owner-ref'd to the CR for GC.
func publishCABundle(ctx context.Context, cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) error {
	name := strings.TrimSpace(p.Spec.PublishCABundleConfigMap)
	if name == "" {
		return nil
	}
	ca, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
	if err != nil {
		return resource.BaoOpErr("reading CA to publish the CA-bundle ConfigMap", p.Spec.Path, err)
	}
	if ca == nil || strings.TrimSpace(ca.Certificate) == "" {
		return nil
	}
	cert := ca.Certificate

	var cm corev1.ConfigMap
	getErr := cl.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: name}, &cm)
	switch {
	case getErr == nil:
		if strings.TrimSpace(cm.Data[caBundleKey]) == strings.TrimSpace(cert) {
			return nil // already current
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[caBundleKey] = cert
		if err := cl.Update(ctx, &cm); err != nil {
			return fmt.Errorf("%w: updating CA-bundle ConfigMap %q: %v", resource.ErrInternal, name, err)
		}
		return nil
	case apierrors.IsNotFound(getErr):
		newCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: p.Namespace,
				// Copy the CR's labels (the chart stamps the tenant label) so a
				// trust-manager Bundle / operator can discover the CA by tenant.
				Labels: p.Labels,
			},
			Data: map[string]string{caBundleKey: cert},
		}
		if err := controllerutil.SetControllerReference(p, newCM, scheme); err != nil {
			return fmt.Errorf("%w: setting owner reference on CA-bundle ConfigMap %q: %v", resource.ErrInternal, name, err)
		}
		if err := cl.Create(ctx, newCM); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("%w: creating CA-bundle ConfigMap %q: %v", resource.ErrInternal, name, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: reading CA-bundle ConfigMap %q: %v", resource.ErrInternal, name, getErr)
	}
}

// readPublishedCABundle returns the ca.crt content of the named ConfigMap, or
// "" when it doesn't exist yet (so the drift check treats it as needing a write).
func readPublishedCABundle(ctx context.Context, cl client.Client, namespace, name string) (string, error) {
	var cm corev1.ConfigMap
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &cm)
	switch {
	case err == nil:
		return cm.Data[caBundleKey], nil
	case apierrors.IsNotFound(err):
		return "", nil
	default:
		return "", fmt.Errorf("%w: reading CA-bundle ConfigMap %q: %v", resource.ErrInternal, name, err)
	}
}

// baoWriteIntermediateInternal runs the single-pass in-bao signing flow:
// ensure the CSR (generate once, persist in a Secret) → sign it with the root
// mount referenced by internalSign.Name (in the CR's own openbaoNamespace) →
// set-signed → read the resulting CA serial.
func baoWriteIntermediateInternal(ctx context.Context, cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, rec record.EventRecorder, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig], error) {
	csr, reused, err := ensureCSRSecret(ctx, cl, scheme, bao, p, ns)
	if err != nil {
		return nil, err
	}
	// Before the sign call, so a mount whose key is gone costs no signature
	// from the signing CA (cross-namespace and audited in hierarchy mode) and
	// imports no keyless issuer. Bao signs here with no human in the loop, so a
	// mismatched CSR has nothing to protect.
	var regenerated bool
	if reused {
		hasKey, err := mountHoldsKey(ctx, bao, p, ns)
		if err != nil {
			return nil, err
		}
		if !hasKey {
			if csr, err = regenerateCSRSecret(ctx, cl, bao, p, ns); err != nil {
				return nil, err
			}
			regenerated = true
		}
	}
	rootMount := strings.Trim(p.Spec.InternalSign.Name, "/")
	// The CSR is generated (above) and bound (below) in the intermediate's own
	// namespace; only the sign call targets the signing CA's namespace. Empty
	// internalSign.openbaoNamespace ⇒ sign in the intermediate's own namespace
	// (historical same-namespace behavior).
	rootNS := ns
	if rns := strings.TrimSpace(p.Spec.InternalSign.OpenBaoNamespace); rns != "" {
		rootNS = baoclient.WithNamespace(rns)
	}
	// The signed intermediate's lifetime is capped by the SIGNING (root)
	// mount's max_lease_ttl, not this intermediate's own mount. The root's own
	// OpenBaoPKISecretEngineConfig sizes that mount to its spec.TTL when it
	// generates, so a hierarchy honors this intermediate's spec.TTL as long as
	// the signing root's TTL is at least as large.
	signed, err := bao.SignIntermediate(ctx, rootMount, csr, signIntermediateInput(p), rootNS)
	if err != nil {
		// Name the signing mount + namespace so a cross-namespace sign
		// failure is diagnosable from the Ready condition. %w keeps the
		// underlying *StatusError so ClassifyErr still sees Forbidden/BaoError.
		signNS := strings.TrimSpace(p.Spec.InternalSign.OpenBaoNamespace)
		if signNS == "" {
			signNS = p.OpenBaoNamespace()
		}
		return nil, fmt.Errorf("signing intermediate CSR with CA mount %q in openbao namespace %q: %w", rootMount, signNS, err)
	}
	if err := bao.SetSignedIntermediate(ctx, p.Spec.Path, signed, ns); err != nil {
		return nil, err
	}
	serial, err := readCASerial(ctx, bao, p, ns)
	if err != nil {
		return nil, err
	}
	if regenerated {
		reportCARegenerated(ctx, rec, p, serial)
	}
	return finishActive(ctx, cl, scheme, bao, p, ns, serial, true)
}

// baoWriteIntermediateExternal runs the multi-pass offline-root flow. Pass 1
// generates the CSR and creates the CSR Secret, then returns
// ErrAwaitingExternalSignature. Subsequent passes wait (without regenerating —
// R4) until the externally-signed cert appears in externalSignSecret, then
// set-signed and activate.
func baoWriteIntermediateExternal(ctx context.Context, cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig], error) {
	exists, err := csrSecretExists(ctx, cl, p)
	if err != nil {
		return nil, err
	}
	if !exists {
		// First pass: generate the CSR and persist it for the offline signer.
		if _, _, err := ensureCSRSecret(ctx, cl, scheme, bao, p, ns); err != nil {
			return nil, err
		}
		return nil, awaitingErr(p)
	}

	// CSR already generated+stored. Look for the externally-signed cert.
	signedCert, err := readExternalSignedCert(ctx, cl, p)
	if err != nil {
		if errors.Is(err, errSignedCertMissing) {
			return nil, awaitingErr(p)
		}
		return nil, err
	}
	// Here rather than earlier so the passes spent waiting cost nothing.
	// Regenerating would replace the private key and invalidate the very
	// certificate someone signed offline, so report and stop before set-signed.
	hasKey, err := mountHoldsKey(ctx, bao, p, ns)
	if err != nil {
		return nil, err
	}
	if !hasKey {
		return nil, resource.BaoOpErr("binding the externally-signed certificate", p.Spec.Path,
			fmt.Errorf("%w — mount holds no private key, so the signed certificate in secret %q "+
				"cannot be bound; the CSR in secret %q was generated from a key bao no longer has. "+
				"Delete secret %q to generate a new CSR, then have it signed again by the offline root",
				baoclient.ErrNotFound, externalSignSecretName(p), csrSecretName(p), csrSecretName(p)))
	}
	if err := bao.SetSignedIntermediate(ctx, p.Spec.Path, signedCert, ns); err != nil {
		return nil, err
	}
	serial, err := readCASerial(ctx, bao, p, ns)
	if err != nil {
		return nil, err
	}
	return finishActive(ctx, cl, scheme, bao, p, ns, serial, true)
}

// readCASerial reads the active CA after set-signed to capture its serial.
// Designed-in fallback: we don't depend on set-signed's response shape.
func readCASerial(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (string, error) {
	const op = "reading CA serial after set-signed"
	ca, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
	switch {
	case errors.Is(err, baoclient.ErrNotFound):
		// set-signed succeeded but the mount has no issuer: the stored CSR came
		// from a key bao no longer holds. Regenerating is the only recovery,
		// and the CSR Secret is what gates it.
		return "", resource.BaoOpErr(op, p.Spec.Path,
			fmt.Errorf("%w — mount has no issuer, so the stored CSR does not match any key in bao; "+
				"delete Secret %q in namespace %q to regenerate the CSR",
				err, csrSecretName(p), p.Namespace))
	case err != nil:
		return "", resource.BaoOpErr(op, p.Spec.Path, err)
	}
	if ca == nil {
		return "", nil
	}
	return ca.SerialNumber, nil
}

// csrSecretName is the deterministic name of the CSR Secret for this CR.
func csrSecretName(p *v1alpha1.OpenBaoPKISecretEngineConfig) string {
	return p.Name + csrSecretSuffix
}

// externalSignSecretName names the Secret the offline-signed certificate is
// read from. Empty when unset, which IsValid rejects for type=intermediate.
func externalSignSecretName(p *v1alpha1.OpenBaoPKISecretEngineConfig) string {
	if p.Spec.ExternalSignSecret == nil {
		return ""
	}
	return p.Spec.ExternalSignSecret.Name
}

// reportCARegenerated records that the operator minted replacement CA material
// without being asked to.
//
// Warning, not Normal: the CR ends up Ready, but certificates the previous CA
// signed cannot be renewed and must be re-issued. Name constraints are in the
// message because the replacement is built from the CR's current spec, so it is
// not necessarily like-for-like.
//
// Unlike the base's Event, this one is not suppressed when the status patch
// fails: it reports a bao-side fact that holds either way.
func reportCARegenerated(ctx context.Context, rec record.EventRecorder, p *v1alpha1.OpenBaoPKISecretEngineConfig, serial string) {
	domains := "none"
	if len(p.Spec.PermittedDnsDomains) > 0 {
		domains = strings.Join(p.Spec.PermittedDnsDomains, ",")
	}
	msg := fmt.Sprintf(
		"regenerated the intermediate CSR for mount %q because bao held no private key for the stored one, "+
			"and signed a replacement CA (serial %s, permittedDnsDomains: %s). "+
			"Certificates issued by the previous CA must be re-issued",
		p.Spec.Path, serial, domains)
	log.FromContext(ctx).Info(msg, "mount", p.Spec.Path, "caSerial", serial,
		"openbaoNamespace", p.OpenBaoNamespace())
	if rec != nil {
		rec.Event(p, corev1.EventTypeWarning, reasonCARegenerated, msg)
	}
}

// csrSecretExists reports whether the CSR Secret is present, without reading
// its body. A read failure other than NotFound is a controller-side error.
func csrSecretExists(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig) (bool, error) {
	var sec corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: csrSecretName(p)}, &sec)
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("%w: reading CSR secret %q: %v", resource.ErrInternal, csrSecretName(p), err)
	}
}

// ensureCSRSecret returns the intermediate CSR, generating it in bao and
// persisting it in an owner-ref'd Secret on first call. If the Secret already
// exists its stored CSR is returned verbatim — never regenerated — so a retry
// after a downstream failure reuses the same key (R4).
//
// reused reports which of those two happened: a stored CSR is only as good as
// the key bao still holds for it, a fresh one always matches. Callers gate the
// mountHoldsKey probe on it so a first bring-up costs no extra call.
func ensureCSRSecret(ctx context.Context, cl client.Client, scheme *runtime.Scheme, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (csr string, reused bool, err error) {
	var sec corev1.Secret
	err = cl.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: csrSecretName(p)}, &sec)
	switch {
	case err == nil:
		if stored := strings.TrimSpace(string(sec.Data[csrSecretKey])); stored != "" {
			return stored, true, nil
		}
		return "", false, fmt.Errorf("%w: CSR secret %q exists but has no %q key", resource.ErrInternal, csrSecretName(p), csrSecretKey)
	case apierrors.IsNotFound(err):
		// Generate + create below.
	default:
		return "", false, fmt.Errorf("%w: reading CSR secret %q: %v", resource.ErrInternal, csrSecretName(p), err)
	}

	csr, err = bao.GenerateIntermediateCSR(ctx, p.Spec.Path, intermediateGenInput(p), ns)
	if err != nil {
		return "", false, err
	}
	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      csrSecretName(p),
			Namespace: p.Namespace,
		},
		Data: map[string][]byte{csrSecretKey: []byte(csr)},
	}
	if err := controllerutil.SetControllerReference(p, newSec, scheme); err != nil {
		return "", false, fmt.Errorf("%w: setting owner reference on CSR secret %q: %v", resource.ErrInternal, csrSecretName(p), err)
	}
	if err := cl.Create(ctx, newSec); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Raced with another reconcile that created the Secret; re-read it.
			if gErr := cl.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: csrSecretName(p)}, &sec); gErr == nil {
				if c := strings.TrimSpace(string(sec.Data[csrSecretKey])); c != "" {
					return c, true, nil
				}
			}
		}
		return "", false, fmt.Errorf("%w: creating CSR secret %q: %v", resource.ErrInternal, csrSecretName(p), err)
	}
	return csr, false, nil
}

// mountHoldsKey reports whether the PKI mount still holds key material.
//
// The CSR Secret lives in Kubernetes and survives a mount being emptied, so a
// stored CSR can outlive its key. Signing it and calling set-signed both
// succeed and import a certificate bao cannot match to a key, leaving the mount
// without a default issuer and the CR unable to complete.
//
// Only ErrNotFound means "no key": a 403 read as an empty mount would re-key a
// healthy intermediate whose policy merely lost a grant.
//
// Answers "any key at all", not "the key for this CSR" — bao exposes no public
// key for a stored key. A mount that lost its key and then had one generated
// out of band still lands on readCASerial's not-found.
func mountHoldsKey(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (bool, error) {
	_, err := bao.ListPKIKeys(ctx, p.Spec.Path, ns)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, baoclient.ErrNotFound):
		return false, nil
	default:
		return false, resource.BaoOpErr("listing PKI keys to check the stored CSR", p.Spec.Path, err)
	}
}

// regenerateCSRSecret generates a new key + CSR on the mount and overwrites the
// stored CSR. Overwrite rather than delete-and-recreate so the Secret is never
// absent for anything watching it.
//
// The Update carries the Get's resourceVersion, so a concurrent writer loses
// rather than silently winning; the retry reapplies the same CSR, still the one
// matching the newest pending key. If it ultimately fails, bao holds a key the
// stored CSR does not match and the next pass lands on readCASerial's
// not-found — degraded and self-reporting, not silent.
func regenerateCSRSecret(ctx context.Context, cl client.Client, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (string, error) {
	csr, err := bao.GenerateIntermediateCSR(ctx, p.Spec.Path, intermediateGenInput(p), ns)
	if err != nil {
		return "", err
	}
	key := client.ObjectKey{Namespace: p.Namespace, Name: csrSecretName(p)}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var sec corev1.Secret
		if err := cl.Get(ctx, key, &sec); err != nil {
			return err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[csrSecretKey] = []byte(csr)
		return cl.Update(ctx, &sec)
	}); err != nil {
		return "", fmt.Errorf("%w: overwriting CSR secret %q with the regenerated CSR: %v",
			resource.ErrInternal, csrSecretName(p), err)
	}
	return csr, nil
}

// errSignedCertMissing marks the externally-signed cert as not yet present.
var errSignedCertMissing = errors.New("external signed certificate not yet present")

// readExternalSignedCert reads the offline-signed cert from externalSignSecret
// under certificateKey (default tls.crt). Returns errSignedCertMissing when
// the Secret or key is absent/empty.
func readExternalSignedCert(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig) (string, error) {
	ref := p.Spec.ExternalSignSecret
	if ref == nil || strings.TrimSpace(ref.Name) == "" {
		// IsValid guarantees this for type=intermediate; defensive.
		return "", fmt.Errorf("%w: spec.externalSignSecret is required", resource.ErrInvalidSpec)
	}
	var sec corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: ref.Name}, &sec)
	switch {
	case err == nil:
	case apierrors.IsNotFound(err):
		return "", errSignedCertMissing
	default:
		return "", fmt.Errorf("%w: reading external sign secret %q: %v", resource.ErrInternal, ref.Name, err)
	}
	key := strings.TrimSpace(p.Spec.CertificateKey)
	if key == "" {
		key = defaultCertificateKey
	}
	cert := strings.TrimSpace(string(sec.Data[key]))
	if cert == "" {
		return "", errSignedCertMissing
	}
	return cert, nil
}

// awaitingErr wraps ErrAwaitingExternalSignature with a message naming the CSR
// Secret to sign and the externalSignSecret to populate.
func awaitingErr(p *v1alpha1.OpenBaoPKISecretEngineConfig) error {
	signSecret := ""
	if p.Spec.ExternalSignSecret != nil {
		signSecret = p.Spec.ExternalSignSecret.Name
	}
	key := strings.TrimSpace(p.Spec.CertificateKey)
	if key == "" {
		key = defaultCertificateKey
	}
	return fmt.Errorf("%w: sign the CSR in secret %q[%s] with your offline root, then place the signed certificate in secret %q[%s]",
		resource.ErrAwaitingExternalSignature, csrSecretName(p), csrSecretKey, signSecret, key)
}

// generateRoot calls the destructive `<path>/root/generate/<privateKeyType>`
// endpoint. Returns the bao response so the caller can stamp the serial onto
// status via the StatusMutator path.
func generateRoot(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	in := baoclient.PKIRootGenerateInput{
		CommonName:     p.Spec.CommonName,
		PrivateKeyType: p.Spec.PrivateKeyType,
		PKIGenCommon:   pkiGenCommonFor(p),
	}
	return bao.GenerateRootPKI(ctx, p.Spec.Path, in, ns)
}

// intermediateGenInput builds the body for intermediate/generate.
func intermediateGenInput(p *v1alpha1.OpenBaoPKISecretEngineConfig) baoclient.PKIIntermediateGenerateInput {
	return baoclient.PKIIntermediateGenerateInput{
		CommonName:     p.Spec.CommonName,
		PrivateKeyType: p.Spec.PrivateKeyType,
		PKIGenCommon:   pkiGenCommonFor(p),
	}
}

// signIntermediateInput builds the body for root/sign-intermediate. Name
// constraints (permittedDnsDomains) are applied here per RFC 5280.
func signIntermediateInput(p *v1alpha1.OpenBaoPKISecretEngineConfig) baoclient.PKISignIntermediateInput {
	return baoclient.PKISignIntermediateInput{
		CommonName:          p.Spec.CommonName,
		TTL:                 durationString(p.Spec.TTL),
		MaxPathLength:       p.Spec.MaxPathLength,
		Format:              p.Spec.Format,
		PermittedDnsDomains: p.Spec.PermittedDnsDomains,
	}
}

// pkiGenCommonFor maps the shared subject/SAN/key spec fields onto the client's
// generate-body input.
func pkiGenCommonFor(p *v1alpha1.OpenBaoPKISecretEngineConfig) baoclient.PKIGenCommon {
	return baoclient.PKIGenCommon{
		TTL:                 durationString(p.Spec.TTL),
		KeyType:             p.Spec.KeyType,
		KeyBits:             p.Spec.KeyBits,
		AltNames:            p.Spec.AltNames,
		IPSans:              p.Spec.IPSans,
		URISans:             p.Spec.URISans,
		OtherSans:           p.Spec.OtherSans,
		Format:              p.Spec.Format,
		PrivateKeyFormat:    p.Spec.PrivateKeyFormat,
		Country:             p.Spec.Country,
		Locality:            p.Spec.Locality,
		Province:            p.Spec.Province,
		StreetAddress:       p.Spec.StreetAddress,
		PostalCode:          p.Spec.PostalCode,
		Organization:        p.Spec.Organization,
		OU:                  p.Spec.OU,
		SerialNumber:        p.Spec.SerialNumber,
		MaxPathLength:       p.Spec.MaxPathLength,
		ExcludeCNFromSAN:    p.Spec.ExcludeCnFromSans,
		PermittedDnsDomains: p.Spec.PermittedDnsDomains,
	}
}

// durationString renders a metav1.Duration as a bao duration, returning ""
// for the zero value so bao applies its own default.
func durationString(d metav1.Duration) string {
	if d.Duration == 0 {
		return ""
	}
	return d.Duration.String()
}

// ensureMountMaxLeaseTTL raises the PKI mount's max_lease_ttl to cover
// spec.TTL before CA generation. bao caps a generated CA cert to the mount's
// max_lease_ttl (default 768h), so without this a long-lived CA (e.g.
// spec.TTL=175200h) is silently issued for only ~32 days. No-op when spec.TTL
// is unset, leaving bao's default.
func ensureMountMaxLeaseTTL(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) error {
	ttl := durationString(p.Spec.TTL)
	if ttl == "" {
		return nil
	}
	return bao.TuneSecretEngine(ctx, p.Spec.Path, baoclient.SecretEngineMountSpec{MaxLeaseTTL: ttl}, ns)
}

func writeURLs(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) error {
	in := baoclient.PKIURLsInput{
		IssuingCertificates:   p.Spec.IssuingCertificates,
		CRLDistributionPoints: p.Spec.CRLDistributionPoints,
		OCSPServers:           p.Spec.OCSPServers,
	}
	return bao.WritePKIURLs(ctx, p.Spec.Path, in, ns)
}

// urlsEqual reports whether the bao read shape matches the spec's URL fields
// (order-insensitive on each list — bao stores them as sets). Returns true
// when both sides are effectively empty.
func urlsEqual(current *baoclient.PKIURLsInput, p *v1alpha1.OpenBaoPKISecretEngineConfig) bool {
	curIssuing, curCRL, curOCSP := []string(nil), []string(nil), []string(nil)
	if current != nil {
		curIssuing = current.IssuingCertificates
		curCRL = current.CRLDistributionPoints
		curOCSP = current.OCSPServers
	}
	return sortedSlicesEqual(p.Spec.IssuingCertificates, curIssuing) &&
		sortedSlicesEqual(p.Spec.CRLDistributionPoints, curCRL) &&
		sortedSlicesEqual(p.Spec.OCSPServers, curOCSP)
}

func sortedSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// checkPKIConfigCollision returns ErrNameCollision when another
// OpenBaoPKISecretEngineConfig CR (different UID) targets the same
// (openbaoNamespace, path) tuple. Two CRs at the same path in different OpenBao
// namespaces don't collide; same path + same ns does. Tie-break: older
// CreationTimestamp wins; on tie, lex order of <namespace>/<name>.
func checkPKIConfigCollision(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig) error {
	var all v1alpha1.OpenBaoPKISecretEngineConfigList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoPKISecretEngineConfigs for collision check: %v",
			resource.ErrInternal, err)
	}
	targetPath := p.BaoName()
	targetNS := p.OpenBaoNamespace()
	mineKey := p.Namespace + "/" + p.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == p.UID {
			continue
		}
		if other.BaoName() != targetPath {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&p.CreationTimestamp):
			otherWins = true
		case p.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: PKI mount %q (ns=%q) already owned by OpenBaoPKISecretEngineConfig %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a GenerationChangedPredicate
// so status writes do not trigger re-reconciles. The external-signature flow
// converges via the base's ErrorBackoff requeue while awaiting; the CSR Secret
// is owner-ref'd to the CR so it is garbage-collected on delete without a
// Secret watch.
func (r *OpenBaoPKISecretEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoPKISecretEngineConfig{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
