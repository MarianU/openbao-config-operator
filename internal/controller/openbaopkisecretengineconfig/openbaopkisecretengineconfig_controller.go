package openbaopkisecretengineconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineconfigs/finalizers,verbs=update

// OpenBaoPKISecretEngineConfigFinalizer follows the Kubernetes
// convention <resource>.<group>/finalizer.
const OpenBaoPKISecretEngineConfigFinalizer = "openbaopkisecretengineconfig.security.mto.stakater.com/finalizer"

type OpenBaoPKISecretEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]
}

// NewOpenBaoPKISecretEngineConfigReconciler constructs the reconciler.
// Bao address + token come from VAULT_ADDR / VAULT_TOKEN at startup.
func NewOpenBaoPKISecretEngineConfigReconciler(mgr ctrl.Manager) (*OpenBaoPKISecretEngineConfigReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoPKISecretEngineConfigReconcilerWithClient(mgr, bao), nil
}

// NewOpenBaoPKISecretEngineConfigReconcilerWithClient is the
// test-friendly constructor.
func NewOpenBaoPKISecretEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoPKISecretEngineConfigReconciler {
	return &OpenBaoPKISecretEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoPKISecretEngineConfig](
			mgr, OpenBaoPKISecretEngineConfigFinalizer,
			OpenBaoPKISecretEngineConfigHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoPKISecretEngineConfigHandlers builds the bao-I/O callbacks.
//
// BaoGet probes for an existing CA and reads URL config in one
// payload. The boolean caExists is the BaoWrite gate: a present CA
// must NEVER be regenerated (would destroy the private key); BaoWrite
// only generates when caExists=false.
func OpenBaoPKISecretEngineConfigHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoPKISecretEngineConfig {
			return &v1alpha1.OpenBaoPKISecretEngineConfig{}
		},

		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) (map[string]any, error) {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			ca, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
			var caSerial string
			switch {
			case err == nil && ca != nil:
				caSerial = ca.SerialNumber
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
			return map[string]any{
				"caExists": true,
				"caSerial": caSerial,
				"urls":     urlsMap,
			}, nil
		},

		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig], error) {
			if err := checkPKIConfigCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())

			// Re-probe inside BaoWrite so a concurrent reconcile that
			// raced past us doesn't get its CA overwritten. The base's
			// drift path already called ReadPKICA, but the result is
			// not threaded down — paying the extra GET is cheap and
			// the destructive-overwrite footgun is severe.
			existing, err := bao.ReadPKICA(ctx, p.Spec.Path, ns)
			var serial string
			switch {
			case err == nil && existing != nil:
				// CA already present; capture serial.
				serial = existing.SerialNumber
			case errors.Is(err, baoclient.ErrNotFound):
				resp, err := generateRoot(ctx, bao, p, ns)
				if err != nil {
					return nil, err
				}
				if resp != nil {
					serial = resp.SerialNumber
				}
			case err != nil:
				return nil, err
			}

			// Skip the URL write when bao's current URL config
			// already matches the spec — saves a round-trip on
			// every URL-only drift loop.
			currentURLs, err := bao.ReadPKIURLs(ctx, p.Spec.Path, ns)
			if err != nil {
				return nil, err
			}
			if !urlsEqual(currentURLs, p.Spec.URLs) {
				if err := writeURLs(ctx, bao, p, ns); err != nil {
					return nil, err
				}
			}

			// Mutator stamps Phase + CASerialNumber atomically with
			// the base's Ready=True patch. No side-channel patch.
			return func(cur *v1alpha1.OpenBaoPKISecretEngineConfig) {
				cur.MarkActive(serial)
			}, nil
		},

		Backfill: func(p *v1alpha1.OpenBaoPKISecretEngineConfig, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineConfig] {
			// Steady-state path: bao matches desired, BaoWrite did not
			// run, but the CR's status may have been left without
			// Phase/CASerialNumber by an earlier transient patch
			// failure (or because this CR is adopting a CA the
			// previous controller version created without stamping
			// status). Backfill is invoked by the base after a
			// no-drift BaoGet so primitives can complete their status
			// from observed state.
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

		BaoDelete: func(ctx context.Context, _ *v1alpha1.OpenBaoPKISecretEngineConfig) error {
			// Never reached: IsDeletable=false short-circuits this in
			// the base. Wired as a safety in case a future spec change
			// flips IsDeletable to true — without disabling the mount,
			// we don't have a "delete CA" surface and would have to
			// handle the no-op explicitly. Returning nil here keeps
			// the contract well-defined either way.
			return nil
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoPKISecretEngineConfig, _, _ string) error {
			// Never reached: the base's rename-cleanup path skips
			// BaoDeleteIdentity when IsDeletable=false. See the type
			// comment for the orphan-by-design rationale.
			return nil
		},

		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineConfig) error {
			return checkPKIConfigCollision(ctx, cl, p)
		},
	}
}

// generateRoot calls the destructive `pki/root/generate/internal`
// endpoint. Returns the bao response so the caller can stamp the
// serial onto status via the StatusMutator path — keeping primitive-
// specific status fields in the same MergeFrom patch as the base's
// Ready=True flip (no side-channel Status().Patch).
func generateRoot(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	in := baoclient.PKIRootGenerateInput{
		CommonName: p.Spec.CommonName,
		TTL:        p.Spec.TTL,
		KeyType:    p.Spec.KeyType,
		KeyBits:    p.Spec.KeyBits,
	}
	if p.Spec.Subject != nil {
		in.Country = p.Spec.Subject.Country
		in.Locality = p.Spec.Subject.Locality
		in.Province = p.Spec.Subject.Province
		in.StreetAddress = p.Spec.Subject.StreetAddress
		in.PostalCode = p.Spec.Subject.PostalCode
		in.Organization = p.Spec.Subject.Organization
		in.OU = p.Spec.Subject.OU
	}
	return bao.GenerateRootPKI(ctx, p.Spec.Path, in, ns)
}

func writeURLs(ctx context.Context, bao baoclient.Client, p *v1alpha1.OpenBaoPKISecretEngineConfig, ns baoclient.CallOption) error {
	in := baoclient.PKIURLsInput{}
	if p.Spec.URLs != nil {
		in.IssuingCertificates = p.Spec.URLs.IssuingCertificates
		in.CRLDistributionPoints = p.Spec.URLs.CRLDistributionPoints
		in.OCSPServers = p.Spec.URLs.OCSPServers
	}
	return bao.WritePKIURLs(ctx, p.Spec.Path, in, ns)
}

// urlsEqual reports whether the bao read shape matches the spec's
// URLs (order-insensitive on each list — bao stores them as sets).
// Returns true when both sides are effectively empty.
func urlsEqual(current *baoclient.PKIURLsInput, spec *v1alpha1.PKIURLs) bool {
	specIssuing, specCRL, specOCSP := []string(nil), []string(nil), []string(nil)
	if spec != nil {
		specIssuing = spec.IssuingCertificates
		specCRL = spec.CRLDistributionPoints
		specOCSP = spec.OCSPServers
	}
	curIssuing, curCRL, curOCSP := []string(nil), []string(nil), []string(nil)
	if current != nil {
		curIssuing = current.IssuingCertificates
		curCRL = current.CRLDistributionPoints
		curOCSP = current.OCSPServers
	}
	return sortedSlicesEqual(specIssuing, curIssuing) &&
		sortedSlicesEqual(specCRL, curCRL) &&
		sortedSlicesEqual(specOCSP, curOCSP)
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
// (openbaoNamespace, path) tuple. Two CRs at the same path in
// different OpenBao namespaces don't collide; same path + same ns
// does. Tie-break: older CreationTimestamp wins; on tie, lex order of
// <namespace>/<name>.
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

// SetupWithManager registers the controller with a
// GenerationChangedPredicate so status writes do not trigger
// re-reconciles.
func (r *OpenBaoPKISecretEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoPKISecretEngineConfig{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func newBaoFromEnv() (baoclient.Client, error) {
	addr, ok := os.LookupEnv("VAULT_ADDR")
	if !ok || addr == "" {
		addr = os.Getenv("BAO_ADDR")
	}
	token, ok := os.LookupEnv("VAULT_TOKEN")
	if !ok || token == "" {
		token = os.Getenv("BAO_TOKEN")
	}
	if addr == "" || token == "" {
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoPKISecretEngineConfigReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
