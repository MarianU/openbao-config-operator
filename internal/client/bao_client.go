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
type Client interface {
	CheckKVv2Mount(ctx context.Context, mount string) (bool, error)
	CheckAuthMount(ctx context.Context, mount string) (bool, error)
	EnableAuthMount(ctx context.Context, mount string, typ string) error

	UpsertPolicy(ctx context.Context, name, rules string) error
	GetPolicy(ctx context.Context, name string) (string, error)
	DeletePolicy(ctx context.Context, name string) error

	UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec) error
	GetK8sRole(ctx context.Context, authMount, roleName string) (*K8sRole, error)
	DeleteK8sRole(ctx context.Context, authMount, roleName string) error
}

// ErrNotFound is the sentinel returned by every Get* when the object does
// not exist on the bao side. Callers use errors.Is to match.
var ErrNotFound = errors.New("bao object not found")

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

// ---- Mounts ----

func (c *sdkClient) CheckKVv2Mount(ctx context.Context, mount string) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	mounts, err := c.v.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := mounts[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kv" && m.Options["version"] == "2", nil
}

func (c *sdkClient) CheckAuthMount(ctx context.Context, mount string) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.v.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kubernetes", nil
}

func (c *sdkClient) EnableAuthMount(ctx context.Context, mount, typ string) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	if typ == "" {
		return errors.New("auth type is empty")
	}
	err := c.v.Sys().EnableAuthWithOptionsWithContext(ctx, mount, &vault.EnableAuthOptions{Type: typ})
	if err != nil && isAlreadyInUse(err) {
		return nil
	}
	return wrapStatus(err)
}

// ---- Policies ----

func (c *sdkClient) UpsertPolicy(ctx context.Context, name, rules string) error {
	return wrapStatus(c.v.Sys().PutPolicyWithContext(ctx, name, rules))
}

func (c *sdkClient) GetPolicy(ctx context.Context, name string) (string, error) {
	// vault/api swallows 404 internally and returns ("", nil) for missing
	// policies. We translate that to ErrNotFound so callers get a uniform
	// missing signal across the interface. An empty-but-present policy is
	// indistinguishable from missing here; callers that care must guard
	// against ever writing an empty body (see Policy.IsValid).
	body, err := c.v.Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return "", wrapStatus(err)
	}
	if body == "" {
		return "", ErrNotFound
	}
	return body, nil
}

func (c *sdkClient) DeletePolicy(ctx context.Context, name string) error {
	err := c.v.Sys().DeletePolicyWithContext(ctx, name)
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

func (c *sdkClient) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec) error {
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
	_, err := c.v.Logical().WriteWithContext(ctx, path, data)
	return wrapStatus(err)
}

func (c *sdkClient) GetK8sRole(ctx context.Context, authMount, roleName string) (*K8sRole, error) {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	sec, err := c.v.Logical().ReadWithContext(ctx, path)
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

func (c *sdkClient) DeleteK8sRole(ctx context.Context, authMount, roleName string) error {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	_, err := c.v.Logical().DeleteWithContext(ctx, path)
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
