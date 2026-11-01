package resource

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

// Context key for the per-reconcile resolved bao client injected by the base
// reconcile loop (mirrors how the kube client is passed under the untyped
// "kubeClient" key). Typed pointer key avoids collisions.
type baoClientKey struct{}

// ConnectionReferer is implemented by every primitive CR that must select a
// connection: it exposes the OpenBaoConnection the CR references.
type ConnectionReferer interface {
	ConnectionRef() *v1alpha1.ConnectionRef
	GetNamespace() string
}

// BaoResolver resolves the bao client a primitive CR should use for a
// reconcile by dereferencing the CR's OpenBaoConnection and building a
// per-connection client (transport/TLS/auth) from it. Implemented by the
// connection package; injected on each controller by main.go. When a
// VaultResource has a nil BaoResolver (test struct literals), the base skips
// resolution and handlers fall back to the client they were constructed with.
type BaoResolver interface {
	Resolve(ctx context.Context, cl client.Client, obj ConnectionReferer) (baoclient.Client, error)
}

// WithBaoClient stores the resolved client in ctx for the handler calls
// (BaoGet/BaoWrite/BaoDelete) that run after the base resolves it.
func WithBaoClient(ctx context.Context, bao baoclient.Client) context.Context {
	return context.WithValue(ctx, baoClientKey{}, bao)
}

// BaoClientFromContext returns the per-reconcile resolved client injected by
// the base, or nil when none is present (no resolver configured / test path).
func BaoClientFromContext(ctx context.Context) baoclient.Client {
	if v, ok := ctx.Value(baoClientKey{}).(baoclient.Client); ok {
		return v
	}
	return nil
}

// BaoClientFromContextOr returns the per-reconcile resolved client injected by
// the base when present, else fallback. Handlers that want to honor a
// per-connection OpenBaoConnection wrap this around the client they were
// constructed with: in production the base injects the resolved client (so the
// ctx one wins); in tests no resolution runs, so the fallback (the fake) is
// used and the existing suites keep passing untouched.
func BaoClientFromContextOr(ctx context.Context, fallback baoclient.Client) baoclient.Client {
	if c := BaoClientFromContext(ctx); c != nil {
		return c
	}
	return fallback
}
