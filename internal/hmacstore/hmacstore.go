// Package hmacstore manages a stable HMAC key used to detect
// rotation of bao-redacted Secret-sourced fields (token-reviewer JWT,
// OIDC client_secret, kubernetes CA cert).
//
// Background. Bao redacts these fields on read (the response omits
// them entirely or returns "<n>_set: true"). The reconciler can't
// compare the resolved Secret value against bao's echo, so a naive
// drift comparator either (a) suppresses the comparison and misses
// rotations or (b) fires drift on every reconcile and write-storms
// bao. Storing an HMAC of the resolved values in the CR's status —
// recomputed on every reconcile and compared against
// status.lastWrittenSecretMac — gives the reconciler a deterministic
// "did the Secret content change since last write" signal without
// keeping cleartext anywhere persistent.
//
// HMAC-SHA256 (rather than plain SHA-256) prevents an attacker who
// can read CR status from rainbow-tabling low-entropy secret values.
// The key is generated once on first bootstrap and stored in a
// controller-owned Secret, mirroring the
// hashicorp/vault-secrets-operator vso-client-cache pattern.
package hmacstore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretKey is the data key inside the controller-owned Secret that
// holds the HMAC key. Constant so kubectl-edit / external bootstrap
// scripts target a known field.
const SecretKey = "key"

// keyLen is 32 bytes (256 bits) — matches the HMAC-SHA256 block size,
// avoids both under- and over-keying.
const keyLen = 32

// Computer computes a deterministic, key-bound MAC over a sequence of
// byte slices. Length-prefixing each slice prevents concat-confusion
// (Compute("ab","c") and Compute("a","bc") return different MACs).
type Computer interface {
	Compute(values ...[]byte) string
}

type computer struct {
	key []byte
}

func (c *computer) Compute(values ...[]byte) string {
	h := hmac.New(sha256.New, c.key)
	var lenBuf [8]byte
	for _, v := range values {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(v)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(v)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// NewComputerFromKey builds a Computer over an existing key. Exported
// for tests; production callers go through Bootstrap.
func NewComputerFromKey(key []byte) Computer {
	return &computer{key: append([]byte(nil), key...)}
}

// Bootstrap returns a Computer keyed by an HMAC key persisted in a
// controller-owned Secret at namespace/name. If the Secret doesn't
// exist, a fresh 32-byte random key is generated and the Secret is
// created. Concurrent operator instances racing the create both end
// up using whichever instance's Secret won the race — see the
// AlreadyExists branch.
//
// TODO(rbac-scope): Bootstrap targets exactly one Secret in the
// operator's own namespace, but config/rbac currently grants
// secrets create+update cluster-wide via the manager ClusterRole.
// Scope-down work: keep get;list;watch on the ClusterRole (the
// auth-config Secret-watches need it across tenant namespaces) and
// move create;update to a namespace-scoped Role + RoleBinding in the
// operator namespace. Out of scope for the HMAC fix PR.
func Bootstrap(ctx context.Context, c client.Client, name, namespace string) (Computer, error) {
	if name == "" || namespace == "" {
		return nil, fmt.Errorf("hmacstore: name and namespace must be non-empty")
	}
	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &sec)
	switch {
	case err == nil:
		// Secret already exists — fall through to extract key.
	case apierrors.IsNotFound(err):
		key := make([]byte, keyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("hmacstore: generating key: %w", err)
		}
		sec = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Data:       map[string][]byte{SecretKey: key},
		}
		if cerr := c.Create(ctx, &sec); cerr != nil {
			if !apierrors.IsAlreadyExists(cerr) {
				return nil, fmt.Errorf("hmacstore: creating Secret %s/%s: %w", namespace, name, cerr)
			}
			// A racing operator instance created it first; re-read.
			if rerr := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &sec); rerr != nil {
				return nil, fmt.Errorf("hmacstore: re-reading Secret %s/%s after create race: %w", namespace, name, rerr)
			}
		}
	default:
		return nil, fmt.Errorf("hmacstore: reading Secret %s/%s: %w", namespace, name, err)
	}

	key, ok := sec.Data[SecretKey]
	if !ok || len(key) == 0 {
		return nil, fmt.Errorf("hmacstore: Secret %s/%s has no %q data", namespace, name, SecretKey)
	}
	return &computer{key: append([]byte(nil), key...)}, nil
}
