package openbaoconnection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// TestReconcile_WritesReadyFalseOnUnreachableBao drives the connection
// controller's standalone Reconcile against an unreachable bao address and
// asserts the Ready condition is persisted to status. This guards the
// status-write path: a bare Status().Update was observed failing silently in
// production (status never persisted); writeStatus now patches via MergeFrom
// inside RetryOnConflict.
func TestReconcile_WritesReadyFalseOnUnreachableBao(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.OpenBaoConnection{}).
		Build()

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "probe-token", Namespace: "vault"},
		Data:       map[string][]byte{"token": []byte("s.probe")},
	}
	conn := &v1alpha1.OpenBaoConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "openbao", Namespace: "vault"},
		Spec: v1alpha1.OpenBaoConnectionSpec{
			Address: "https://127.0.0.1:1",
			Auth: v1alpha1.OpenBaoConnectionAuth{
				Method: v1alpha1.AuthMethodToken,
				Token:  &v1alpha1.OpenBaoTokenAuth{TokenSecretRef: v1alpha1.SecretRef{Name: "probe-token", Key: "token"}},
			},
			TLS: v1alpha1.OpenBaoConnectionTLS{},
		},
	}

	ctx := context.Background()
	require.NoError(t, cl.Create(ctx, sec))
	require.NoError(t, cl.Create(ctx, conn))

	r := NewReconciler(cl)
	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "vault", Name: "openbao"}})
	require.NoError(t, err)
	// Result may carry Requeue (error recovery) or RequeueAfter (healthy
	// re-probe). Both are valid; the important contract is status persistence.
	_ = result

	got := &v1alpha1.OpenBaoConnection{}
	require.NoError(t, cl.Get(ctx, types.NamespacedName{Namespace: "vault", Name: "openbao"}, got))
	require.Len(t, got.Status.Conditions, 1, "status conditions must be persisted")
	require.Equal(t, resource.ConditionReady, got.Status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionFalse, got.Status.Conditions[0].Status)
	require.NotEmpty(t, got.Status.Conditions[0].Reason)
	// LastTransitionTime is Required by the metav1.Condition schema; missing it
	// makes the CRD reject the write (the original production bug).
	require.False(t, got.Status.Conditions[0].LastTransitionTime.IsZero())
}
