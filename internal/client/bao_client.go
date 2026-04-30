// Package client is the wrapper (facade) layer over hashicorp/vault/api.
//
// Callers (ClusterAuth, Tenant, the VCO-origin primitive controllers) depend
// only on the Client interface below. This file wires each method to the
// corresponding vault/api call, so callers never have to know we use the
// SDK internally. The wrapper exists to (1) keep callers SDK-agnostic so
// the implementation is swappable, (2) translate SDK error shapes into the
// project-local *StatusError / ErrNotFound contract every controller
// already classifies on, and (3) centralize idempotency quirks like the
// "path is already in use" 400 from sys/auth. OpenBao is wire-compatible
// with Vault, so all of these calls work unchanged against an OpenBao
// server.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// All Get* methods report a missing object the same way: they return
// ErrNotFound (with the zero value for the data return). Callers classify
// with errors.Is(err, client.ErrNotFound). Other errors retain their
// structured form (*StatusError, network errors, etc.).
//
// Every method accepts variadic CallOptions; the current option set is just
// WithNamespace for scoping a call to an OpenBao namespace. Passing no opts
// targets the root namespace and matches pre-namespace-support behaviour.
type Client interface {
	CheckKVv2Mount(ctx context.Context, mount string, opts ...CallOption) (bool, error)
	CheckAuthMount(ctx context.Context, mount string, opts ...CallOption) (bool, error)
	EnableAuthMount(ctx context.Context, mount string, typ string, opts ...CallOption) error

	// Secret-engine mount lifecycle (sys/mounts/<path>). Used by the
	// OpenBaoSecretEngine controller to manage KV / Transit / PKI mounts.
	// EnableSecretEngine creates the mount; TuneSecretEngine updates
	// tunable fields (description, options) on an existing mount.
	// EnableSecretEngine is idempotent on "path already in use" so the
	// controller can call it unconditionally on the create path; the
	// update path uses TuneSecretEngine because bao's enable endpoint
	// does NOT update an existing mount, it returns 400.
	EnableSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error
	TuneSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error
	GetSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) (*SecretEngineMount, error)
	DisableSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) error

	// Auth-mount read + delete (sys/auth/<path>). EnableAuthMount above
	// owns the create path; these handle drift inspection and cleanup.
	GetAuthMount(ctx context.Context, mount string, opts ...CallOption) (*AuthMount, error)
	DisableAuthMount(ctx context.Context, mount string, opts ...CallOption) error

	// OpenBao-namespace lifecycle (sys/namespaces/<name>). Used by the
	// OpenBaoNamespace controller. Nested namespaces are addressed via
	// WithNamespace on the parent context, so spec.name stays a single
	// segment in the CRD even for `acme/sub` (parent="acme/", name="sub").
	CreateNamespace(ctx context.Context, name string, opts ...CallOption) error
	GetNamespace(ctx context.Context, name string, opts ...CallOption) (*Namespace, error)
	DeleteNamespace(ctx context.Context, name string, opts ...CallOption) error

	UpsertPolicy(ctx context.Context, name, rules string, opts ...CallOption) error
	GetPolicy(ctx context.Context, name string, opts ...CallOption) (string, error)
	DeletePolicy(ctx context.Context, name string, opts ...CallOption) error

	UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec, opts ...CallOption) error
	GetK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) (*K8sRole, error)
	DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) error

	// PKI secret-engine config (post-mount). GenerateRootPKI is
	// destructive — calling it on a mount that already has a CA
	// overwrites the private key. Callers must guard with ReadPKICA
	// (returns ErrNotFound when no CA is present).
	GenerateRootPKI(ctx context.Context, mount string, in PKIRootGenerateInput, opts ...CallOption) (*PKICAResponse, error)
	ReadPKICA(ctx context.Context, mount string, opts ...CallOption) (*PKICAResponse, error)
	WritePKIURLs(ctx context.Context, mount string, in PKIURLsInput, opts ...CallOption) error
	ReadPKIURLs(ctx context.Context, mount string, opts ...CallOption) (*PKIURLsInput, error)

	// PKI roles (post-mount, post-CA). Roles define what certs may be
	// issued from a given PKI mount.
	WritePKIRole(ctx context.Context, mount, name string, spec PKIRoleSpec, opts ...CallOption) error
	ReadPKIRole(ctx context.Context, mount, name string, opts ...CallOption) (*PKIRoleSpec, error)
	DeletePKIRole(ctx context.Context, mount, name string, opts ...CallOption) error
}

// PKIRoleSpec mirrors the bao API surface for /<mount>/roles/<name>.
// Fields the controller doesn't currently surface in the CR spec are
// added as the spec grows; bao defaults fill in the rest.
type PKIRoleSpec struct {
	AllowedDomains    []string
	AllowSubdomains   bool
	AllowBareDomains  bool
	AllowAnyName      bool
	EnforceHostnames  bool
	AllowIPSANs       bool
	AllowGlobDomains  bool
	ServerFlag        bool
	ClientFlag        bool
	CodeSigningFlag   bool
	EmailProtection   bool
	KeyType           string // rsa | ec | ed25519 | any
	KeyBits           int
	KeyUsage          []string
	ExtKeyUsage       []string
	TTL               string
	MaxTTL            string
	GenerateLease bool
	NoStore       bool
	RequireCN     bool
}

// PKIRootGenerateInput is the body for /<mount>/root/generate/internal.
// Only the fields the controller currently exposes through the CR spec
// are present; expand as the spec grows.
type PKIRootGenerateInput struct {
	CommonName       string
	TTL              string
	KeyType          string // rsa | ec | ed25519
	KeyBits          int
	Country          []string
	Locality         []string
	Province         []string
	StreetAddress    []string
	PostalCode       []string
	Organization     []string
	OU               []string
	MaxPathLength    int
	ExcludeCNFromSAN bool
}

// PKICAResponse captures the bao-side data we surface to the controller.
type PKICAResponse struct {
	SerialNumber string
	Certificate  string // PEM
}

// PKIURLsInput / response carry the AIA/CRL distribution metadata.
type PKIURLsInput struct {
	IssuingCertificates   []string
	CRLDistributionPoints []string
	OCSPServers           []string
}

// SecretEngineMountSpec is the write payload for EnableSecretEngine.
// Mirrors the shape vault/api's MountInput exposes — bao stores the same
// fields. Description and Options are nullable on the bao side; we send
// non-empty values only.
type SecretEngineMountSpec struct {
	Type        string
	Description string
	// Options is the engine-specific options map. For kv-v2 the canonical
	// content is {"version": "2"}.
	Options map[string]string
}

// SecretEngineMount is the read shape for GetSecretEngineMount. Stripped
// down from vault/api's MountOutput to the fields the operator's drift
// comparator actually consumes; bao still echoes the rest, but reading
// them here would invite false drift on every server upgrade.
type SecretEngineMount struct {
	Type        string
	Description string
	Options     map[string]string
}

// AuthMount is the read shape for GetAuthMount.
type AuthMount struct {
	Type        string
	Description string
}

// Namespace is the read shape for GetNamespace. Bao echoes more fields
// (custom_metadata, etc.); we keep just what the operator's drift /
// existence checks need. Path is the fully-qualified bao-side path
// including any parent prefix.
type Namespace struct {
	Path string
	ID   string
}

// ErrNotFound is the sentinel returned by every Get* when the object does
// not exist on the bao side. Callers use errors.Is to match.
var ErrNotFound = errors.New("bao object not found")

// CallOption configures a single bao API call. The only option today is
// WithNamespace, which scopes the call to an OpenBao namespace via the
// X-Vault-Namespace header. The variadic shape is forward-compatible: future
// options (timeout overrides, custom headers) can be added without breaking
// existing call sites.
type CallOption func(*callOpts)

type callOpts struct {
	namespace string
}

// WithNamespace scopes the call to an OpenBao namespace (e.g. "acme/" or
// "acme/sub/"). An empty string is equivalent to passing no option — the call
// targets the root namespace. The trailing slash is conventional but not
// required; bao accepts both forms.
func WithNamespace(ns string) CallOption {
	return func(o *callOpts) { o.namespace = ns }
}

// NamespaceFromOpts returns the namespace selected by the supplied call
// options, or "" if no namespace was requested. Exists so test fakes that
// implement Client can mirror the real client's per-call namespace routing
// without reaching into unexported types. Production callers should not
// need this — they pass WithNamespace into the call directly.
func NamespaceFromOpts(opts []CallOption) string {
	var o callOpts
	for _, fn := range opts {
		fn(&o)
	}
	return o.namespace
}

// K8sRoleSpec is the write payload for a Kubernetes auth role. Fields use
// pointer / empty-string sentinels for "unset" so UpsertK8sRole can omit
// keys that the caller did not set — bao distinguishes between "field
// absent" (use mount default) and "field present with zero value" (override
// with that value, e.g. token_num_uses=0 means unlimited).
type K8sRoleSpec struct {
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string
	TokenMaxTTL                   string
	Renewable                     *bool

	// Fields below were added for the KubernetesAuthEngineRole CRD; the
	// Tenant controller leaves them at zero values and they are omitted
	// from the bao request, preserving its historical request shape.
	Audience             string
	AliasNameSource      string
	TokenBoundCIDRs      []string
	TokenExplicitMaxTTL  string
	TokenNoDefaultPolicy *bool
	TokenNumUses         *int
	TokenPeriod          string
	TokenType            string
}

type K8sRole struct {
	Name                          string
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string
	TokenMaxTTL                   string
	Renewable                     *bool

	Audience             string
	AliasNameSource      string
	TokenBoundCIDRs      []string
	TokenExplicitMaxTTL  string
	TokenNoDefaultPolicy *bool
	TokenNumUses         *int
	TokenPeriod          string
	TokenType            string
}

// StatusError wraps an SDK error that carries an HTTP status code. The shared
// reconcile base classifies bao errors by status (403 → Forbidden,
// 404 → NotFound) via errors.As; consolidating the translation here keeps
// callers free of fragile string-matching against error messages, which
// would misclassify e.g. a 500 whose body contains "upstream service not found".
type StatusError struct {
	StatusCode int
	Inner      error
}

func (e *StatusError) Error() string { return e.Inner.Error() }
func (e *StatusError) Unwrap() error { return e.Inner }

// wrapStatus translates SDK-specific *vault.ResponseError into our local
// StatusError. Non-status errors (network, context-cancelled, etc.) pass
// through unchanged.
func wrapStatus(err error) error {
	if err == nil {
		return nil
	}
	var rerr *vault.ResponseError
	if errors.As(err, &rerr) {
		return &StatusError{StatusCode: rerr.StatusCode, Inner: err}
	}
	return err
}

// ---- SDK-backed implementation. ----

type sdkClient struct {
	v *vault.Client
}

// NewHTTPClient constructs a Client backed by hashicorp/vault/api. It
// returns an error rather than a degraded client so misconfiguration
// (empty address, malformed config) surfaces at construction time instead
// of as repeated reconcile-time failures with no diagnostic for the
// operator process itself.
func NewHTTPClient(addr, token string) (Client, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("bao client: address is empty")
	}
	cfg := vault.DefaultConfig()
	cfg.Address = strings.TrimRight(addr, "/")
	v, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("bao client: %w", err)
	}
	v.SetToken(token)
	return &sdkClient{v: v}, nil
}

// underlying is a package-private accessor used by tests in this package.
// Exposing the raw *vault.Client externally would let callers bypass the
// wrapper's status-classification and idempotency contracts, defeating
// the abstraction; the lowercase name keeps the escape hatch in-package
// where compile-time checks catch misuse.
func (c *sdkClient) underlying() *vault.Client { return c.v }

// clientFor returns the vault client to use for this call: either the shared
// top-level client (no opts, or empty namespace) or a derived client with
// X-Vault-Namespace set. Allocating a per-call client only when opts ask for
// it keeps the hot path (root-namespace calls) allocation-free.
func (c *sdkClient) clientFor(opts []CallOption) *vault.Client {
	if len(opts) == 0 {
		return c.v
	}
	var o callOpts
	for _, fn := range opts {
		fn(&o)
	}
	if o.namespace == "" {
		return c.v
	}
	return c.v.WithNamespace(o.namespace)
}

// ---- Mounts ----

func (c *sdkClient) CheckKVv2Mount(ctx context.Context, mount string, opts ...CallOption) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	mounts, err := c.clientFor(opts).Sys().ListMountsWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := mounts[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kv" && m.Options["version"] == "2", nil
}

func (c *sdkClient) CheckAuthMount(ctx context.Context, mount string, opts ...CallOption) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.clientFor(opts).Sys().ListAuthWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kubernetes", nil
}

func (c *sdkClient) EnableAuthMount(ctx context.Context, mount, typ string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	if typ == "" {
		return errors.New("auth type is empty")
	}
	err := c.clientFor(opts).Sys().EnableAuthWithOptionsWithContext(ctx, mount, &vault.EnableAuthOptions{Type: typ})
	if err != nil && isAlreadyInUse(err) {
		return nil
	}
	return wrapStatus(err)
}

func (c *sdkClient) EnableSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	if spec.Type == "" {
		return errors.New("mount type is empty")
	}
	input := &vault.MountInput{
		Type:        spec.Type,
		Description: spec.Description,
		Options:     spec.Options,
	}
	err := c.clientFor(opts).Sys().MountWithContext(ctx, mount, input)
	if err != nil && isAlreadyInUse(err) {
		// Idempotent enable: a mount already at this path with a different
		// type would have surfaced as a different bao error earlier in the
		// reconciler's Get → IsEquivalent → Write path; the only "already
		// in use" we see here is when our own previous reconcile succeeded.
		return nil
	}
	return wrapStatus(err)
}

// TuneSecretEngine updates tunable fields on an existing mount via
// POST /sys/mounts/<path>/tune. Bao's enable endpoint does not update
// an existing mount (it returns 400 "path already in use"), so the
// controller calls this on the update path. Description and Options
// are sent verbatim — Type is mount-immutable and ignored here.
func (c *sdkClient) TuneSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	input := vault.MountConfigInput{
		Description: &spec.Description,
		Options:     spec.Options,
	}
	err := c.clientFor(opts).Sys().TuneMountWithContext(ctx, mount, input)
	return wrapStatus(err)
}

func (c *sdkClient) GetSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) (*SecretEngineMount, error) {
	mount = strings.Trim(mount, "/") + "/"
	mounts, err := c.clientFor(opts).Sys().ListMountsWithContext(ctx)
	if err != nil {
		return nil, wrapStatus(err)
	}
	m, ok := mounts[mount]
	if !ok {
		return nil, ErrNotFound
	}
	return &SecretEngineMount{
		Type:        m.Type,
		Description: m.Description,
		Options:     m.Options,
	}, nil
}

func (c *sdkClient) DisableSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	err := c.clientFor(opts).Sys().UnmountWithContext(ctx, mount)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent: 404 = already gone. Mirrors DeletePolicy.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

func (c *sdkClient) GetAuthMount(ctx context.Context, mount string, opts ...CallOption) (*AuthMount, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.clientFor(opts).Sys().ListAuthWithContext(ctx)
	if err != nil {
		return nil, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return nil, ErrNotFound
	}
	return &AuthMount{
		Type:        m.Type,
		Description: m.Description,
	}, nil
}

func (c *sdkClient) DisableAuthMount(ctx context.Context, mount string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	err := c.clientFor(opts).Sys().DisableAuthWithContext(ctx, mount)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- OpenBao namespaces (sys/namespaces/<name>) ----
//
// vault/api OSS does not expose Sys() helpers for namespaces (Vault treats
// them as Enterprise), so these go through Logical() against the
// sys/namespaces/ paths directly. The wire shape is identical to bao's
// HTTP API.

func (c *sdkClient) CreateNamespace(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.Trim(name, "/")
	if name == "" {
		return errors.New("namespace name is empty")
	}
	// Bao's POST sys/namespaces/<name> is idempotent: re-creating an
	// existing namespace returns success and does not change its ID.
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "sys/namespaces/"+name, nil)
	return wrapStatus(err)
}

func (c *sdkClient) GetNamespace(ctx context.Context, name string, opts ...CallOption) (*Namespace, error) {
	name = strings.Trim(name, "/")
	if name == "" {
		return nil, errors.New("namespace name is empty")
	}
	sec, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "sys/namespaces/"+name)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrNotFound
	}
	return &Namespace{
		Path: asString(sec.Data["path"]),
		ID:   asString(sec.Data["id"]),
	}, nil
}

func (c *sdkClient) DeleteNamespace(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.Trim(name, "/")
	if name == "" {
		return errors.New("namespace name is empty")
	}
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "sys/namespaces/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone. Mirrors DeletePolicy.
	// 400-class responses for "namespace contains children" surface as
	// regular bao errors and the finalizer stays in place — exactly the
	// graceful-block behaviour the controller wants.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Policies ----

func (c *sdkClient) UpsertPolicy(ctx context.Context, name, rules string, opts ...CallOption) error {
	return wrapStatus(c.clientFor(opts).Sys().PutPolicyWithContext(ctx, name, rules))
}

func (c *sdkClient) GetPolicy(ctx context.Context, name string, opts ...CallOption) (string, error) {
	// vault/api swallows 404 internally and returns ("", nil) for missing
	// policies. We translate that to ErrNotFound so callers get a uniform
	// missing signal across the interface. An empty-but-present policy is
	// indistinguishable from missing here; callers that care must guard
	// against ever writing an empty body (see Policy.IsValid).
	body, err := c.clientFor(opts).Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return "", wrapStatus(err)
	}
	if body == "" {
		return "", ErrNotFound
	}
	return body, nil
}

func (c *sdkClient) DeletePolicy(ctx context.Context, name string, opts ...CallOption) error {
	err := c.clientFor(opts).Sys().DeletePolicyWithContext(ctx, name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Kubernetes auth roles ----

func (c *sdkClient) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec, opts ...CallOption) error {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	data := map[string]any{
		"token_policies":                   spec.Policies,
		"bound_service_account_names":      spec.BoundServiceAccountNames,
		"bound_service_account_namespaces": spec.BoundServiceAccountNamespaces,
	}
	if spec.TokenTTL != "" {
		data["token_ttl"] = spec.TokenTTL
	}
	if spec.TokenMaxTTL != "" {
		data["token_max_ttl"] = spec.TokenMaxTTL
	}
	if spec.Renewable != nil {
		data["token_renewable"] = *spec.Renewable
	}
	if spec.Audience != "" {
		data["audience"] = spec.Audience
	}
	if spec.AliasNameSource != "" {
		data["alias_name_source"] = spec.AliasNameSource
	}
	if len(spec.TokenBoundCIDRs) > 0 {
		data["token_bound_cidrs"] = spec.TokenBoundCIDRs
	}
	if spec.TokenExplicitMaxTTL != "" {
		data["token_explicit_max_ttl"] = spec.TokenExplicitMaxTTL
	}
	if spec.TokenNoDefaultPolicy != nil {
		data["token_no_default_policy"] = *spec.TokenNoDefaultPolicy
	}
	if spec.TokenNumUses != nil {
		data["token_num_uses"] = *spec.TokenNumUses
	}
	if spec.TokenPeriod != "" {
		data["token_period"] = spec.TokenPeriod
	}
	if spec.TokenType != "" {
		data["token_type"] = spec.TokenType
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, path, data)
	return wrapStatus(err)
}

func (c *sdkClient) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) (*K8sRole, error) {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	sec, err := c.clientFor(opts).Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrNotFound
	}
	return &K8sRole{
		Name:                          roleName,
		Policies:                      asStringSlice(sec.Data["token_policies"]),
		BoundServiceAccountNames:      asStringSlice(sec.Data["bound_service_account_names"]),
		BoundServiceAccountNamespaces: asStringSlice(sec.Data["bound_service_account_namespaces"]),
		TokenTTL:                      asString(sec.Data["token_ttl"]),
		TokenMaxTTL:                   asString(sec.Data["token_max_ttl"]),
		Renewable:                     asBoolPtr(sec.Data["token_renewable"]),
		Audience:                      asString(sec.Data["audience"]),
		AliasNameSource:               asString(sec.Data["alias_name_source"]),
		TokenBoundCIDRs:               asStringSlice(sec.Data["token_bound_cidrs"]),
		TokenExplicitMaxTTL:           asString(sec.Data["token_explicit_max_ttl"]),
		TokenNoDefaultPolicy:          asBoolPtr(sec.Data["token_no_default_policy"]),
		TokenNumUses:                  asIntPtr(sec.Data["token_num_uses"]),
		TokenPeriod:                   asString(sec.Data["token_period"]),
		TokenType:                     asString(sec.Data["token_type"]),
	}, nil
}

func (c *sdkClient) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) error {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, path)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone. Mirrors DeletePolicy.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- PKI ----

// GenerateRootPKI calls /<mount>/root/generate/internal. DESTRUCTIVE on
// a mount that already has a CA — bao silently overwrites the private
// key. Callers must guard via ReadPKICA first.
func (c *sdkClient) GenerateRootPKI(ctx context.Context, mount string, in PKIRootGenerateInput, opts ...CallOption) (*PKICAResponse, error) {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return nil, errors.New("mount path is empty")
	}
	if strings.TrimSpace(in.CommonName) == "" {
		return nil, errors.New("common_name is required")
	}
	body := map[string]interface{}{"common_name": in.CommonName}
	if in.TTL != "" {
		body["ttl"] = in.TTL
	}
	if in.KeyType != "" {
		body["key_type"] = in.KeyType
	}
	if in.KeyBits > 0 {
		body["key_bits"] = in.KeyBits
	}
	if len(in.Country) > 0 {
		body["country"] = in.Country
	}
	if len(in.Locality) > 0 {
		body["locality"] = in.Locality
	}
	if len(in.Province) > 0 {
		body["province"] = in.Province
	}
	if len(in.StreetAddress) > 0 {
		body["street_address"] = in.StreetAddress
	}
	if len(in.PostalCode) > 0 {
		body["postal_code"] = in.PostalCode
	}
	if len(in.Organization) > 0 {
		body["organization"] = in.Organization
	}
	if len(in.OU) > 0 {
		body["ou"] = in.OU
	}
	if in.MaxPathLength != 0 {
		body["max_path_length"] = in.MaxPathLength
	}
	if in.ExcludeCNFromSAN {
		body["exclude_cn_from_sans"] = true
	}
	path := mount + "/root/generate/internal"
	resp, err := c.clientFor(opts).Logical().WriteWithContext(ctx, path, body)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from %s", path)
	}
	return &PKICAResponse{
		SerialNumber: asString(resp.Data["serial_number"]),
		Certificate:  asString(resp.Data["certificate"]),
	}, nil
}

// ReadPKICA fetches the active CA cert at <mount>/cert/ca. Returns
// ErrNotFound when no CA has been generated yet — bao reports this in
// three different shapes depending on version: 404, 200 with empty
// data, or 400 with the message "no default issuer currently
// configured". We coalesce all three into the canonical not-found
// signal so the controller's "needs create" branch fires
// consistently.
func (c *sdkClient) ReadPKICA(ctx context.Context, mount string, opts ...CallOption) (*PKICAResponse, error) {
	mount = strings.Trim(mount, "/")
	path := mount + "/cert/ca"
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, path)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		// OpenBao 2.x returns 400 + "no default issuer" when the mount
		// is empty. Treat as not-found so the create path fires.
		if strings.Contains(strings.ToLower(err.Error()), "no default issuer") {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	cert := asString(resp.Data["certificate"])
	if cert == "" {
		return nil, ErrNotFound
	}
	return &PKICAResponse{
		SerialNumber: asString(resp.Data["serial_number"]),
		Certificate:  cert,
	}, nil
}

// WritePKIURLs configures the AIA / CRL / OCSP distribution points
// published in every issued cert via <mount>/config/urls. Idempotent.
func (c *sdkClient) WritePKIURLs(ctx context.Context, mount string, in PKIURLsInput, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	body := map[string]interface{}{
		"issuing_certificates":    in.IssuingCertificates,
		"crl_distribution_points": in.CRLDistributionPoints,
		"ocsp_servers":            in.OCSPServers,
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/config/urls", body)
	return wrapStatus(err)
}

// ReadPKIURLs returns the URL config; nil-pointer fields when bao has
// no URLs configured (returns 200 with empty arrays).
func (c *sdkClient) ReadPKIURLs(ctx context.Context, mount string, opts ...CallOption) (*PKIURLsInput, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/config/urls")
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return &PKIURLsInput{}, nil
	}
	return &PKIURLsInput{
		IssuingCertificates:   asStringSlice(resp.Data["issuing_certificates"]),
		CRLDistributionPoints: asStringSlice(resp.Data["crl_distribution_points"]),
		OCSPServers:           asStringSlice(resp.Data["ocsp_servers"]),
	}, nil
}

// WritePKIRole upserts a role at /<mount>/roles/<name>. Bao writes are
// idempotent on the path; calling twice with the same body is a no-op.
func (c *sdkClient) WritePKIRole(ctx context.Context, mount, name string, spec PKIRoleSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || name == "" {
		return errors.New("mount or role name empty")
	}
	body := pkiRoleToMap(spec)
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/roles/"+name, body)
	return wrapStatus(err)
}

// ReadPKIRole fetches the role config. Returns ErrNotFound on 404 or
// 200 with empty data.
func (c *sdkClient) ReadPKIRole(ctx context.Context, mount, name string, opts ...CallOption) (*PKIRoleSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/roles/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return mapToPKIRole(resp.Data), nil
}

// DeletePKIRole removes a role. Idempotent on 404.
func (c *sdkClient) DeletePKIRole(ctx context.Context, mount, name string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, mount+"/roles/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// pkiRoleToMap builds the bao write body from a PKIRoleSpec. Only
// non-zero fields are emitted so bao's defaults stay in effect when
// the CR doesn't override them.
func pkiRoleToMap(s PKIRoleSpec) map[string]interface{} {
	body := map[string]interface{}{}
	if len(s.AllowedDomains) > 0 {
		body["allowed_domains"] = s.AllowedDomains
	}
	if s.AllowSubdomains {
		body["allow_subdomains"] = true
	}
	if s.AllowBareDomains {
		body["allow_bare_domains"] = true
	}
	if s.AllowAnyName {
		body["allow_any_name"] = true
	}
	if s.EnforceHostnames {
		body["enforce_hostnames"] = true
	}
	if s.AllowIPSANs {
		body["allow_ip_sans"] = true
	}
	if s.AllowGlobDomains {
		body["allow_glob_domains"] = true
	}
	if s.ServerFlag {
		body["server_flag"] = true
	}
	if s.ClientFlag {
		body["client_flag"] = true
	}
	if s.CodeSigningFlag {
		body["code_signing_flag"] = true
	}
	if s.EmailProtection {
		body["email_protection_flag"] = true
	}
	if s.KeyType != "" {
		body["key_type"] = s.KeyType
	}
	if s.KeyBits > 0 {
		body["key_bits"] = s.KeyBits
	}
	if len(s.KeyUsage) > 0 {
		body["key_usage"] = s.KeyUsage
	}
	if len(s.ExtKeyUsage) > 0 {
		body["ext_key_usage"] = s.ExtKeyUsage
	}
	if s.TTL != "" {
		body["ttl"] = s.TTL
	}
	if s.MaxTTL != "" {
		body["max_ttl"] = s.MaxTTL
	}
	if s.GenerateLease {
		body["generate_lease"] = true
	}
	if s.NoStore {
		body["no_store"] = true
	}
	if s.RequireCN {
		body["require_cn"] = true
	}
	return body
}

// mapToPKIRole reverses pkiRoleToMap for drift comparisons. Bao
// echoes server-side defaults (e.g. ttl=0, key_bits=2048) so the read
// shape is richer than the write shape; the comparator on the CR side
// does the normalization.
func mapToPKIRole(d map[string]interface{}) *PKIRoleSpec {
	derefBool := func(v any) bool {
		p := asBoolPtr(v)
		if p == nil {
			return false
		}
		return *p
	}
	derefInt := func(v any) int {
		p := asIntPtr(v)
		if p == nil {
			return 0
		}
		return *p
	}
	// TTL fields come back as bao durations: int seconds. Render as a
	// "<n>s" string so the comparator on the CR side can treat them
	// the same way as the spec's bao-duration string ("1h", "3600s").
	durStr := func(v any) string {
		if p := asIntPtr(v); p != nil {
			if *p == 0 {
				return ""
			}
			return fmt.Sprintf("%ds", *p)
		}
		return asString(v)
	}
	out := &PKIRoleSpec{
		AllowedDomains:                asStringSlice(d["allowed_domains"]),
		AllowSubdomains:               derefBool(d["allow_subdomains"]),
		AllowBareDomains:              derefBool(d["allow_bare_domains"]),
		AllowAnyName:                  derefBool(d["allow_any_name"]),
		EnforceHostnames:              derefBool(d["enforce_hostnames"]),
		AllowIPSANs:                   derefBool(d["allow_ip_sans"]),
		AllowGlobDomains:              derefBool(d["allow_glob_domains"]),
		ServerFlag:                    derefBool(d["server_flag"]),
		ClientFlag:                    derefBool(d["client_flag"]),
		CodeSigningFlag:               derefBool(d["code_signing_flag"]),
		EmailProtection:               derefBool(d["email_protection_flag"]),
		KeyType:                       asString(d["key_type"]),
		KeyBits:                       derefInt(d["key_bits"]),
		KeyUsage:                      asStringSlice(d["key_usage"]),
		ExtKeyUsage:   asStringSlice(d["ext_key_usage"]),
		TTL:           durStr(d["ttl"]),
		MaxTTL:        durStr(d["max_ttl"]),
		GenerateLease: derefBool(d["generate_lease"]),
		NoStore:       derefBool(d["no_store"]),
		RequireCN:     derefBool(d["require_cn"]),
	}
	return out
}

// ---- helpers ----

// isAlreadyInUse stays string-based: bao returns 400 with this message text
// for an idempotent re-enable, not a distinct status code, so we have to
// peek at the message body either way.
func isAlreadyInUse(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already in use") || strings.Contains(msg, "path is already in use")
}

func asStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	if is, ok := v.([]any); ok {
		out := make([]string, 0, len(is))
		for _, it := range is {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func asBoolPtr(v any) *bool {
	if v == nil {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// asIntPtr coerces a vault/api response value into *int. vault/api returns
// JSON numbers as json.Number; the helper also accepts native int / int64 /
// float64 because httptest-based unit tests construct response bodies with
// plain Go literals. Returns nil on missing or unrecognized shape so the
// caller can treat "not present" identically to "not parseable".
func asIntPtr(v any) *int {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			n := int(i)
			return &n
		}
	case int:
		return &x
	case int64:
		n := int(x)
		return &n
	case float64:
		n := int(x)
		return &n
	case string:
		if i, err := strconv.Atoi(x); err == nil {
			return &i
		}
	}
	return nil
}
