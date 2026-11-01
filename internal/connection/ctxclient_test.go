package connection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// spyBao delegates to the embedded interface, overriding GetPolicy to prove
// which underlying client a call routed through.
type spyBao struct {
	baoclient.Client
	name string
}

func (s *spyBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return s.name, nil
}

func TestWrapClient_RoutesThroughCtxClient(t *testing.T) {
	fallback := &spyBao{name: "fallback"}
	wrapped := WrapClient(fallback)
	ctx := context.Background()

	// No ctx-resolved client -> falls back to the constructed client.
	got, err := wrapped.GetPolicy(ctx, "x")
	require.NoError(t, err)
	require.Equal(t, "fallback", got, "no ctx client -> fallback used")

	// Base injected a per-connection client -> it wins over the fallback.
	injected := &spyBao{name: "injected"}
	ctx2 := resource.WithBaoClient(ctx, injected)
	got, err = wrapped.GetPolicy(ctx2, "x")
	require.NoError(t, err)
	require.Equal(t, "injected", got, "ctx-resolved client must win")

	// A fresh ctx with a different client routes there instead.
	other := &spyBao{name: "other"}
	ctx3 := resource.WithBaoClient(ctx, other)
	got, err = wrapped.GetPolicy(ctx3, "x")
	require.NoError(t, err)
	require.Equal(t, "other", got, "per-reconcile client follows each ctx")
}

// Compile-time: WrapClient must satisfy the full baoclient.Client interface so
// handlers built with it (inside every primitive constructor) route every bao
// I/O call through the ctx-resolved connection.
var _ baoclient.Client = WrapClient(nil)
