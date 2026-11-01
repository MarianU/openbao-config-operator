// Package connection resolves an OpenBaoConnection CR into a working
// baoclient.Client for a given primitive reconcile, by dereferencing the
// referenced OpenBaoConnection and reading its (Secret-backed) material at
// reconcile time. This is what lets one operator process manage many OpenBao
// instances with per-connection transport + auth, instead of the single
// env-constructed global client.
package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

var _ resource.BaoResolver = Resolver{}

// Resolver implements resource.BaoResolver. It is stateless — every call
// re-reads the OpenBaoConnection CR and its referenced Secrets from the
// apiserver, so a changed connection is picked up without operator state.
type Resolver struct{}

// New returns a Resolver.
func New() Resolver { return Resolver{} }

// Resolve builds the client for the OpenBaoConnection referenced by obj's
// spec.connectionRef. Omitted/unknown ref, invalid connection, or missing
// Secret material all return an error that the base classifies as a
// connection error and surfaces on the CR's Ready=False condition.
func (r Resolver) Resolve(ctx context.Context, cl client.Client, obj resource.ConnectionReferer) (baoclient.Client, error) {
	ref := obj.ConnectionRef()
	if ref == nil || strings.TrimSpace(ref.Name) == "" {
		return nil, fmt.Errorf("spec.connectionRef is required (name of an OpenBaoConnection CR)")
	}
	ns := ref.Namespace
	if ns == "" {
		ns = obj.GetNamespace()
	}
	conn := &v1alpha1.OpenBaoConnection{}
	key := types.NamespacedName{Namespace: ns, Name: ref.Name}
	if err := cl.Get(ctx, key, conn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("openbaoconnection %s not found (referenced by spec.connectionRef)", key)
		}
		return nil, fmt.Errorf("get openbaoconnection %s: %w", key, err)
	}
	return BuildClient(ctx, cl, conn)
}

// BuildClient builds a baoclient.Client for an OpenBaoConnection CR directly
// (used by the connection controller's own health probe and by Resolve).
func BuildClient(ctx context.Context, cl client.Client, conn *v1alpha1.OpenBaoConnection) (baoclient.Client, error) {
	if ok, err := conn.IsValid(); !ok {
		return nil, fmt.Errorf("openbaoconnection %s invalid: %w", conn.Name, err)
	}
	tlsCfg, err := buildTLS(ctx, cl, conn)
	if err != nil {
		return nil, err
	}
	switch conn.Spec.Auth.Method {
	case v1alpha1.AuthMethodToken:
		token, err := readSecretString(ctx, cl, conn, conn.Spec.Auth.Token.TokenSecretRef, "token")
		if err != nil {
			return nil, err
		}
		return baoclient.NewHTTPClientTLS(conn.Spec.Address, token, tlsCfg)
	case v1alpha1.AuthMethodKubernetes:
		return baoclient.NewKubernetesAuthClientTLS(
			conn.Spec.Address, conn.Spec.AuthMount(), conn.Spec.Auth.Kubernetes.Role, conn.Spec.AuthJWTPath(), tlsCfg)
	default:
		return nil, fmt.Errorf("openbaoconnection %s: unknown auth method %q", conn.Name, conn.Spec.Auth.Method)
	}
}

// buildTLS assembles the *tls.Config for a connection from its referenced
// Secrets (all bytes, read live). nil-safe: absent CA uses system roots,
// absent client cert means no mTLS, and a plain (non-TLS) connection just
// gets the TLS1.2 minimum with default verification.
func buildTLS(ctx context.Context, cl client.Client, conn *v1alpha1.OpenBaoConnection) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	s := conn.Spec.TLS
	if s.CACertSecretRef != nil {
		ca, err := readSecretBytes(ctx, cl, conn, *s.CACertSecretRef, "ca.crt")
		if err != nil {
			return nil, fmt.Errorf("connection %s: CA secret: %w", conn.Name, err)
		}
		if len(ca) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("connection %s: CA secret %s contained no parseable PEM certificates",
					conn.Name, s.CACertSecretRef.Name)
			}
			tlsCfg.RootCAs = pool
		}
	}
	if s.ClientCertSecretRef != nil {
		cert, key, err := readClientCert(ctx, cl, conn, *s.ClientCertSecretRef)
		if err != nil {
			return nil, fmt.Errorf("connection %s: client certificate: %w", conn.Name, err)
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("connection %s: load client key pair: %w", conn.Name, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	if s.TLSServerName != "" {
		tlsCfg.ServerName = s.TLSServerName
	}
	if s.Insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	return tlsCfg, nil
}

func secretKey(ref v1alpha1.SecretRef, def string) string {
	if ref.Key != "" {
		return ref.Key
	}
	return def
}

func readSecretBytes(ctx context.Context, cl client.Client, conn *v1alpha1.OpenBaoConnection, ref v1alpha1.SecretRef, defKey string) ([]byte, error) {
	ns := conn.ResolvedNamespace(&ref)
	sec := &corev1.Secret{}
	key := types.NamespacedName{Namespace: ns, Name: ref.Name}
	if err := cl.Get(ctx, key, sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s not found", key)
		}
		return nil, fmt.Errorf("get secret %s: %w", key, err)
	}
	v, ok := sec.Data[secretKey(ref, defKey)]
	if !ok {
		return nil, fmt.Errorf("secret %s has no key %q", key, secretKey(ref, defKey))
	}
	return v, nil
}

func readSecretString(ctx context.Context, cl client.Client, conn *v1alpha1.OpenBaoConnection, ref v1alpha1.SecretRef, defKey string) (string, error) {
	b, err := readSecretBytes(ctx, cl, conn, ref, defKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// readClientCert returns the tls.crt / tls.key pair from a kubernetes.io/tls
// Secret referenced for mutual TLS.
func readClientCert(ctx context.Context, cl client.Client, conn *v1alpha1.OpenBaoConnection, ref v1alpha1.SecretRef) ([]byte, []byte, error) {
	ns := conn.ResolvedNamespace(&ref)
	sec := &corev1.Secret{}
	key := types.NamespacedName{Namespace: ns, Name: ref.Name}
	if err := cl.Get(ctx, key, sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("secret %s not found", key)
		}
		return nil, nil, fmt.Errorf("get secret %s: %w", key, err)
	}
	cert, okC := sec.Data["tls.crt"]
	priv, okK := sec.Data["tls.key"]
	if !okC || !okK || len(cert) == 0 || len(priv) == 0 {
		return nil, nil, fmt.Errorf("secret %s must be a kubernetes.io/tls secret with tls.crt and tls.key", key)
	}
	return cert, priv, nil
}
