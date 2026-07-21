package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// ------------ Client ------------

type BaoClient struct {
	BaseURL     string
	Token       string
	K8sAuthPath string // e.g. "kubernetes" (default) or "k8s-prod"
	http        *http.Client
}

// NewBaoClientFromEnv builds a client from VAULT_* env vars.
// Required: VAULT_ADDR, VAULT_TOKEN
// Optional: VAULT_K8S_AUTH_PATH (default "kubernetes")
func NewBaoClientFromEnv() *BaoClient {
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	tok := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if addr == "" || tok == "" {
		panic("VAULT_ADDR and VAULT_TOKEN must be set for E2E")
	}
	// Normalize: strip trailing slash and any /ui/... suffix users might paste
	addr = strings.TrimRight(addr, "/")
	if i := strings.Index(addr, "/ui/"); i >= 0 {
		addr = addr[:i]
	}
	k8sPath := os.Getenv("VAULT_K8S_AUTH_PATH")
	if k8sPath == "" {
		k8sPath = "kubernetes"
	}

	return &BaoClient{
		BaseURL:     addr,
		Token:       tok,
		K8sAuthPath: strings.Trim(k8sPath, "/"),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *BaoClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.Token) // Vault/OpenBao-compatible
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func readBody(r io.Reader, max int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return string(b)
}

func statusErr(resp *http.Response, prefix string) error {
	body := readBody(resp.Body, 4096)
	return fmt.Errorf("%s: HTTP %d: %s", prefix, resp.StatusCode, strings.TrimSpace(body))
}

// ------------ Mounts (/v1/sys/mounts) ------------

// tolerate "options" being either an object or a string
type mountEntry struct {
	Type       string          `json:"type"`
	RawOptions json.RawMessage `json:"options"`
	Options    map[string]string
}

func (m *mountEntry) normalize() {
	m.Options = map[string]string{}
	if len(m.RawOptions) == 0 || string(m.RawOptions) == "null" {
		return
	}
	// preferred/object form
	var mp map[string]string
	if err := json.Unmarshal(m.RawOptions, &mp); err == nil {
		m.Options = mp
		return
	}
	// fallback/string form
	var s string
	if err := json.Unmarshal(m.RawOptions, &s); err == nil {
		if v := extractKVVersion(s); v != "" {
			m.Options["version"] = v
		}
		return
	}
}

var (
	reVersionEq = regexp.MustCompile(`(^|[,;\s])version\s*=\s*([0-9]+)($|[,;\s])`)
	reMapStyle  = regexp.MustCompile(`\bversion\s*:\s*([0-9]+)\b`)
)

func extractKVVersion(s string) string {
	if m := reVersionEq.FindStringSubmatch(s); len(m) == 4 {
		return m[2]
	}
	if m := reMapStyle.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

type Mounts struct {
	byPath map[string]mountEntry
}

func (m Mounts) HasKVv2(path string) bool {
	if len(m.byPath) == 0 {
		return false
	}
	want := strings.Trim(path, "/")
	// Fast path: exact keys (with or without slash)
	if me, ok := m.byPath[want+"/"]; ok {
		me.normalize()
		return strings.EqualFold(me.Type, "kv") && me.Options["version"] == "2"
	}
	if me, ok := m.byPath[want]; ok {
		me.normalize()
		return strings.EqualFold(me.Type, "kv") && me.Options["version"] == "2"
	}
	// Normalize scan
	for k, me := range m.byPath {
		if strings.Trim(k, "/") == want {
			me.normalize()
			return strings.EqualFold(me.Type, "kv") && me.Options["version"] == "2"
		}
	}
	return false
}

func (c *BaoClient) ListMounts(ctx context.Context) (Mounts, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/sys/mounts", nil)
	if err != nil {
		return Mounts{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return Mounts{}, statusErr(resp, "mounts")
	}
	raw := readBody(resp.Body, 1<<20) // 1MB cap

	// 1) wrapped: {"data": { "<mount>/": {...} } }
	var wrapped struct {
		Data map[string]mountEntry `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil && wrapped.Data != nil {
		return Mounts{byPath: wrapped.Data}, nil
	}

	// 2) flat: { "<mount>/": {...} }
	var flat map[string]mountEntry
	if err := json.Unmarshal([]byte(raw), &flat); err == nil && flat != nil {
		return Mounts{byPath: flat}, nil
	}

	// 3) some servers: {"data":{"mounts":{...}}}
	var triple struct {
		Data struct {
			Mounts map[string]mountEntry `json:"mounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &triple); err == nil && triple.Data.Mounts != nil {
		return Mounts{byPath: triple.Data.Mounts}, nil
	}

	// If we got here, show a tiny prefix to aid debugging.
	snip := raw
	if len(snip) > 256 {
		snip = snip[:256] + "…"
	}
	return Mounts{}, fmt.Errorf("unexpected /v1/sys/mounts response shape: %s", snip)
}

// ------------ Policy (/v1/sys/policies/acl/<name>) ------------

func (c *BaoClient) GetPolicy(ctx context.Context, name string) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/sys/policies/acl/"+name, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("policy %q not found", name)
	}
	if resp.StatusCode >= 300 {
		return "", statusErr(resp, "get policy "+name)
	}
	raw := readBody(resp.Body, 1<<20)

	// wrapped: {"data":{"rules":"...","policy":"..."}}
	var wrapped struct {
		Data struct {
			Rules  string `json:"rules"`
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil {
		if wrapped.Data.Policy != "" {
			return wrapped.Data.Policy, nil
		}
		if wrapped.Data.Rules != "" {
			return wrapped.Data.Rules, nil
		}
	}

	// flat: {"rules":"..."} or {"policy":"..."}
	var flat struct {
		Rules  string `json:"rules"`
		Policy string `json:"policy"`
	}
	if err := json.Unmarshal([]byte(raw), &flat); err == nil {
		if flat.Policy != "" {
			return flat.Policy, nil
		}
		if flat.Rules != "" {
			return flat.Rules, nil
		}
	}

	return "", errors.New("unexpected policy response format")
}

// ------------ PKI (/v1/<mount>/...) ------------

// GetPKICACert reads the CA cert PEM at /v1/<mount>/cert/ca. Returns a
// "not found"-flavoured error when the mount has no CA yet (bao 2.x emits 400
// "no default issuer" for an empty mount).
func (c *BaoClient) GetPKICACert(ctx context.Context, mount string) (string, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.do(ctx, http.MethodGet, "/v1/"+mount+"/cert/ca", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw := readBody(resp.Body, 1<<20)
	if resp.StatusCode == http.StatusNotFound ||
		(resp.StatusCode == http.StatusBadRequest && strings.Contains(raw, "no default issuer")) {
		return "", fmt.Errorf("pki CA at %q not found", mount)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("get pki ca %q: HTTP %d: %s", mount, resp.StatusCode, strings.TrimSpace(raw))
	}
	var wrapped struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil && wrapped.Data.Certificate != "" {
		return wrapped.Data.Certificate, nil
	}
	// Some mounts return the raw PEM directly (Accept text/plain fallback).
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		return raw, nil
	}
	return "", errors.New("unexpected pki ca response format")
}

// SignIntermediate signs a CSR with the root mount and returns the signed
// intermediate certificate PEM. Used by the offline-signer e2e path.
func (c *BaoClient) SignIntermediate(ctx context.Context, rootMount, csr string) (string, error) {
	rootMount = strings.Trim(rootMount, "/")
	buf, err := json.Marshal(map[string]any{
		"csr":    csr,
		"format": "pem_bundle",
		"ttl":    "43800h",
	})
	if err != nil {
		return "", err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/"+rootMount+"/root/sign-intermediate", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw := readBody(resp.Body, 1<<20)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("sign-intermediate on %q: HTTP %d: %s", rootMount, resp.StatusCode, strings.TrimSpace(raw))
	}
	var wrapped struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil && wrapped.Data.Certificate != "" {
		return wrapped.Data.Certificate, nil
	}
	return "", errors.New("unexpected sign-intermediate response format")
}

// ------------ Identity OIDC keys (/v1/identity/oidc/key/<name>) ------------

// WriteIdentityOIDCKey creates or overwrites an OIDC signing key. The
// typed baoclient.Client does not expose this endpoint (the operator
// doesn't manage OIDC keys), but OpenBaoIdentityTokenRole needs a
// pre-existing key to reference, so the e2e setup writes one directly.
func (c *BaoClient) WriteIdentityOIDCKey(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/identity/oidc/key/"+name,
		strings.NewReader(`{"allowed_client_ids":"*","algorithm":"RS256"}`))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return statusErr(resp, "write identity oidc key "+name)
	}
	return nil
}

// DeleteIdentityOIDCKey removes an OIDC signing key. Returns nil on a
// 2xx; returns ErrIdentityOIDCKeyNotFound on a 404 so callers can
// distinguish "already deleted" (acceptable in AfterAll cleanup) from
// "path typo" (the test fixture is wrong and was silently passing
// against an empty bao). Other non-2xx surfaces verbatim.
func (c *BaoClient) DeleteIdentityOIDCKey(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/identity/oidc/key/"+name, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrIdentityOIDCKeyNotFound
	}
	return statusErr(resp, "delete identity oidc key "+name)
}

// ErrIdentityOIDCKeyNotFound is the sentinel returned by
// DeleteIdentityOIDCKey when the key does not exist on the bao side.
// Callers that legitimately tolerate "already deleted" (e.g. AfterAll
// cleanup) should explicitly match this with errors.Is; callers that
// asserted prior existence should treat it as a test bug.
var ErrIdentityOIDCKeyNotFound = errors.New("identity oidc key not found")

// ------------ K8s Role (/v1/auth/<mount>/role/<name>) ------------

type K8sRole struct {
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	Policies                      []string
}

func (c *BaoClient) GetK8sRole(ctx context.Context, name string) (*K8sRole, error) {
	path := fmt.Sprintf("/v1/auth/%s/role/%s", c.K8sAuthPath, name)
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("k8s role %q not found (mount=%q)", name, c.K8sAuthPath)
	}
	if resp.StatusCode >= 300 {
		return nil, statusErr(resp, "get k8s role "+name)
	}
	raw := readBody(resp.Body, 1<<20)

	// wrapped
	var wrapped struct {
		Data struct {
			BoundSANs []string `json:"bound_service_account_names"`
			BoundNS   []string `json:"bound_service_account_namespaces"`
			Policies  []string `json:"policies"`
			TokenPols []string `json:"token_policies"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil &&
		(len(wrapped.Data.BoundSANs) > 0 ||
			len(wrapped.Data.BoundNS) > 0 ||
			len(wrapped.Data.Policies) > 0 ||
			len(wrapped.Data.TokenPols) > 0) {
		pols := wrapped.Data.Policies
		if len(pols) == 0 {
			pols = wrapped.Data.TokenPols
		}
		return &K8sRole{
			BoundServiceAccountNames:      wrapped.Data.BoundSANs,
			BoundServiceAccountNamespaces: wrapped.Data.BoundNS,
			Policies:                      pols,
		}, nil
	}

	// flat
	var flat struct {
		BoundSANs []string `json:"bound_service_account_names"`
		BoundNS   []string `json:"bound_service_account_namespaces"`
		Policies  []string `json:"policies"`
		TokenPols []string `json:"token_policies"`
	}
	if err := json.Unmarshal([]byte(raw), &flat); err == nil &&
		(len(flat.BoundSANs) > 0 || len(flat.BoundNS) > 0 || len(flat.Policies) > 0 || len(flat.TokenPols) > 0) {
		pols := flat.Policies
		if len(pols) == 0 {
			pols = flat.TokenPols
		}
		return &K8sRole{
			BoundServiceAccountNames:      flat.BoundSANs,
			BoundServiceAccountNamespaces: flat.BoundNS,
			Policies:                      pols,
		}, nil
	}

	return nil, errors.New("unexpected role response format")
}
