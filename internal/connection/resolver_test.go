package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
)

// referer adapts a *v1alpha1.OpenBaoPolicy (which implements ConnectionRef)
// into the resource.ConnectionReferer input Resolve expects.
func referer(ref *v1alpha1.ConnectionRef) *v1alpha1.OpenBaoPolicy {
	p := &v1alpha1.OpenBaoPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ai", Name: "p"}}
	p.Spec.ConnectionRef = ref
	return p
}

func tokenConnection(ns string, tokenSecret string) *v1alpha1.OpenBaoConnection {
	c := &v1alpha1.OpenBaoConnection{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"}}
	c.Spec.Address = "https://bao.example:8200"
	c.Spec.Auth.Method = v1alpha1.AuthMethodToken
	c.Spec.Auth.Token = &v1alpha1.OpenBaoTokenAuth{
		TokenSecretRef: v1alpha1.SecretRef{Name: tokenSecret},
	}
	return c
}

func TestResolve_RequiresRef(t *testing.T) {
	cl := fake.NewClientBuilder().Build()
	_, err := Resolver{}.Resolve(context.Background(), cl, referer(nil))
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "connectionref is required")
}

func TestResolve_MissingConnection(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(scheme()).Build()
	p := referer(&v1alpha1.ConnectionRef{Name: "nope"})
	_, err := Resolver{}.Resolve(context.Background(), cl, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestResolve_CrossNamespaceRef(t *testing.T) {
	conn := tokenConnection("vault", "bao-token")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "vault", Name: "bao-token"},
		Data:       map[string][]byte{"token": []byte("s.abc")},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(conn, secret).Build()
	p := referer(&v1alpha1.ConnectionRef{Name: "default", Namespace: "vault"})
	_, err := Resolver{}.Resolve(context.Background(), cl, p)
	require.NoError(t, err, "token client built from cross-namespace connection")
}

func TestResolve_InvalidConnection(t *testing.T) {
	conn := tokenConnection("ai", "bao-token")
	conn.Spec.Auth.Method = "bogus"
	cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(conn).Build()
	p := referer(&v1alpha1.ConnectionRef{Name: "default"})
	_, err := Resolver{}.Resolve(context.Background(), cl, p)
	require.Error(t, err)
}

func TestResolve_MissingTokenSecret(t *testing.T) {
	conn := tokenConnection("ai", "bao-token")
	cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(conn).Build()
	p := referer(&v1alpha1.ConnectionRef{Name: "default"})
	_, err := Resolver{}.Resolve(context.Background(), cl, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}
