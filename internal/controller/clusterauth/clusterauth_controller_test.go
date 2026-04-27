package clusterauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	obxv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, obxv1alpha1.AddToScheme(s))
	return s
}

func makeCR(ns, name string, mutate func(*obxv1alpha1.OpenBaoExtension)) *obxv1alpha1.OpenBaoExtension {
	cr := &obxv1alpha1.OpenBaoExtension{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: obxv1alpha1.OpenBaoExtensionSpec{
			Server: obxv1alpha1.ServerSpec{
				URL: "http://placeholder", // replaced per test
				TokenSecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "bao-token"},
					Key:                  "token",
				},
			},
		},
	}
	if mutate != nil {
		mutate(cr)
	}
	return cr
}

func baoServer(status int, body any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/auth" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch b := body.(type) {
		case []byte:
			_, _ = w.Write(b)
		default:
			_ = json.NewEncoder(w).Encode(b)
		}
	}))
}

func getCond(t *testing.T, cr *obxv1alpha1.OpenBaoExtension, typ string) *metav1.Condition {
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == typ {
			return &cr.Status.Conditions[i]
		}
	}
	t.Fatalf("condition %q not found", typ)
	return nil
}

func Test_Reconcile_StatusContracts(t *testing.T) {
	scheme := newScheme(t)
	ctx := context.Background()

	type tc struct {
		name          string
		baoStatus     int
		baoBody       any
		expectReason  string
		expectStatus  metav1.ConditionStatus
		expectRequeue time.Duration
	}

	unwrapped := map[string]any{
		"token/":      map[string]any{"type": "token"},
		"kubernetes/": map[string]any{"type": "kubernetes"},
	}
	wrapped := map[string]any{"data": unwrapped}

	cases := []tc{
		{
			name:          "present-unwrapped",
			expectReason:  "Success",
			expectStatus:  metav1.ConditionTrue,
			expectRequeue: 5 * time.Minute,
			baoStatus:     200, baoBody: unwrapped,
		},
		{
			name:          "present-wrapped",
			expectReason:  "Success",
			expectStatus:  metav1.ConditionTrue,
			expectRequeue: 5 * time.Minute,
			baoStatus:     200, baoBody: wrapped,
		},
		{
			name:          "missing",
			expectReason:  "WaitingForDependencies",
			expectStatus:  metav1.ConditionFalse,
			expectRequeue: 30 * time.Second,
			baoStatus:     200, baoBody: map[string]any{"token/": map[string]any{"type": "token"}},
		},
		{
			name:          "bao-error-500",
			expectReason:  "Error",
			expectStatus:  metav1.ConditionFalse,
			expectRequeue: 30 * time.Second,
			baoStatus:     500, baoBody: map[string]any{"error": "boom"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Fake client with CR + Secret
			token := []byte("s.x")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "bao-token", Namespace: "ns"},
				Data:       map[string][]byte{"token": token},
			}
			cr := makeCR("ns", "ex", nil)

			fc := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cr, secret).
				WithStatusSubresource(cr).
				Build()

			srv := baoServer(c.baoStatus, c.baoBody)
			defer srv.Close()

			r := &ClusterAuthReconciler{
				Client: fc,
				Scheme: scheme,
			}

			// point URL to test server
			cr.Spec.Server.URL = srv.URL
			require.NoError(t, fc.Update(ctx, cr))

			res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "ex"}})
			require.NoError(t, err)
			require.WithinDuration(t, time.Now().Add(c.expectRequeue), time.Now().Add(res.RequeueAfter), time.Second)

			var got obxv1alpha1.OpenBaoExtension
			require.NoError(t, fc.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "ex"}, &got))

			cond := getCond(t, &got, "AuthConfigured")
			require.Equal(t, c.expectStatus, cond.Status)
			require.Equal(t, c.expectReason, cond.Reason)
			require.Equal(t, got.Generation, cond.ObservedGeneration)
		})
	}
}

// Server URL "/" passes the early non-empty check at clusterauth_controller.go:63
// but reduces to "" after TrimRight, which fails NewHTTPClient. The reconciler
// must surface this as AuthConfigured=False/Error and back off, not return an
// error to the manager that would loop without status visibility.
func Test_Reconcile_NewHTTPClientFailureSurfacesAsStatus(t *testing.T) {
	scheme := newScheme(t)
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bao-token", Namespace: "ns"},
		Data:       map[string][]byte{"token": []byte("s.x")},
	}
	cr := makeCR("ns", "ex", func(c *obxv1alpha1.OpenBaoExtension) {
		c.Spec.Server.URL = "/" // becomes "" after TrimRight, fails NewHTTPClient
	})

	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, secret).
		WithStatusSubresource(cr).
		Build()

	r := &ClusterAuthReconciler{Client: fc, Scheme: scheme}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "ex"}})
	require.NoError(t, err, "constructor failures must not bubble up to the manager — status is the contract")
	require.Equal(t, 30*time.Second, res.RequeueAfter, "should back off, not hot-loop")

	var got obxv1alpha1.OpenBaoExtension
	require.NoError(t, fc.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "ex"}, &got))
	cond := getCond(t, &got, "AuthConfigured")
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, "Error", cond.Reason)
	require.Contains(t, cond.Message, "address is empty",
		"the constructor's failure reason must reach the user via status.message")
}
