package hmacstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testSecretName = "hmac-key"

func newFakeClient(t *testing.T, objs ...runtime.Object) *crfake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	b := crfake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		b = b.WithRuntimeObjects(objs...)
	}
	return b
}

func TestCompute_Deterministic_AndKeyDependent(t *testing.T) {
	t.Parallel()
	c1 := NewComputerFromKey([]byte("key-one"))
	c2 := NewComputerFromKey([]byte("key-two"))

	a := c1.Compute([]byte("hello"), []byte("world"))
	b := c1.Compute([]byte("hello"), []byte("world"))
	require.Equal(t, a, b, "same key, same input must yield same MAC")

	d := c2.Compute([]byte("hello"), []byte("world"))
	require.NotEqual(t, a, d, "different keys must yield different MACs")
}

// Length-prefixing must prevent concat-confusion: Compute("ab","c")
// and Compute("a","bc") have different MACs.
func TestCompute_NoConcatConfusion(t *testing.T) {
	t.Parallel()
	c := NewComputerFromKey([]byte("key"))
	require.NotEqual(t,
		c.Compute([]byte("ab"), []byte("c")),
		c.Compute([]byte("a"), []byte("bc")),
	)
}

func TestBootstrap_GeneratesAndPersistsKey(t *testing.T) {
	t.Parallel()
	cl := newFakeClient(t).Build()
	c1, err := Bootstrap(context.Background(), cl, testSecretName, "ns")
	require.NoError(t, err)
	require.NotNil(t, c1)

	// Re-bootstrap from the now-existing Secret returns a Computer that
	// produces the same MAC for the same input.
	c2, err := Bootstrap(context.Background(), cl, testSecretName, "ns")
	require.NoError(t, err)
	require.Equal(t,
		c1.Compute([]byte("payload")),
		c2.Compute([]byte("payload")),
		"second bootstrap must read the same persisted key")
}

func TestBootstrap_ReadsExistingSecret(t *testing.T) {
	t.Parallel()
	pre := &corev1.Secret{}
	pre.Name = testSecretName
	pre.Namespace = "ns"
	pre.Data = map[string][]byte{SecretKey: []byte("static-test-key-32-bytes-long-aa")}
	cl := newFakeClient(t, pre).Build()

	c, err := Bootstrap(context.Background(), cl, testSecretName, "ns")
	require.NoError(t, err)
	require.NotNil(t, c)

	expected := NewComputerFromKey([]byte("static-test-key-32-bytes-long-aa")).
		Compute([]byte("payload"))
	require.Equal(t, expected, c.Compute([]byte("payload")))
}

func TestBootstrap_RejectsSecretMissingKeyData(t *testing.T) {
	t.Parallel()
	pre := &corev1.Secret{}
	pre.Name = testSecretName
	pre.Namespace = "ns"
	pre.Data = map[string][]byte{} // missing "key"
	cl := newFakeClient(t, pre).Build()

	_, err := Bootstrap(context.Background(), cl, testSecretName, "ns")
	require.Error(t, err)
	require.Contains(t, err.Error(), `has no "key"`)
}

func TestBootstrap_ValidatesArgs(t *testing.T) {
	t.Parallel()
	cl := newFakeClient(t).Build()
	_, err := Bootstrap(context.Background(), cl, "", "ns")
	require.Error(t, err)
	_, err = Bootstrap(context.Background(), cl, "name", "")
	require.Error(t, err)
}

// raceClient wraps an underlying client and forces the AlreadyExists
// branch in Bootstrap: Get returns NotFound on the first call, Create
// returns AlreadyExists, and the underlying store is pre-populated so
// the second Get (the re-read after AlreadyExists) returns a real
// Secret. Models the race where two operator instances both miss on
// Get and one's Create wins.
type raceClient struct {
	client.Client
	getCount int
	target   client.ObjectKey
	persist  *corev1.Secret
}

func (r *raceClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == r.target {
		r.getCount++
		if r.getCount == 1 {
			return apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "secrets"}, key.Name)
		}
		// Subsequent Gets return the persisted Secret as the "winner"
		// of the race.
		sec := obj.(*corev1.Secret)
		*sec = *r.persist
		return nil
	}
	return r.Client.Get(ctx, key, obj, opts...)
}

func (r *raceClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if sec, ok := obj.(*corev1.Secret); ok &&
		client.ObjectKeyFromObject(sec) == r.target {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "secrets"}, sec.Name)
	}
	return r.Client.Create(ctx, obj, opts...)
}

// Bootstrap_RaceLost exercises the AlreadyExists re-read branch: when
// our Create races with another instance, we re-read the winner's
// Secret instead of erroring out, and produce a Computer keyed by
// whatever the winner persisted.
func TestBootstrap_RaceLost_ReReadsWinnerSecret(t *testing.T) {
	t.Parallel()
	winnerKey := []byte("winner-key-32-bytes-long-aabbccdd")
	persisted := &corev1.Secret{}
	persisted.Name = testSecretName
	persisted.Namespace = "ns"
	persisted.Data = map[string][]byte{SecretKey: winnerKey}

	inner := newFakeClient(t).Build()
	rc := &raceClient{
		Client:  inner,
		target:  client.ObjectKey{Namespace: "ns", Name: testSecretName},
		persist: persisted,
	}

	c, err := Bootstrap(context.Background(), rc, testSecretName, "ns")
	require.NoError(t, err, "AlreadyExists must be handled, not propagated")
	require.NotNil(t, c)
	require.Equal(t, 2, rc.getCount, "must Get a second time after AlreadyExists")

	// The Computer must use the WINNER's key, not a freshly-generated
	// local one — otherwise different operator instances disagree on MAC.
	expected := NewComputerFromKey(winnerKey).Compute([]byte("payload"))
	require.Equal(t, expected, c.Compute([]byte("payload")))
}
