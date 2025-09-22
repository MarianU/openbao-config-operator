package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ---- Local constants (client package scope) ----

const (
	// API paths
	pathSysAuth        = "/v1/sys/auth"
	pathSysMounts      = "/v1/sys/mounts"
	pathPolicyPrefix   = "/v1/sys/policies/acl/"
	pathAuthRoleFormat = "/v1/auth/%s/role/%s"

	// HTTP headers / values
	hdrVaultToken  = "X-Vault-Token"
	hdrContentType = "Content-Type"
	ctJSON         = "application/json"

	// API type strings (server-side conventions)
	authTypeKubernetes = "kubernetes"
	kvType             = "kv"
	kvVersionV2        = "2"
)

// ---- Public interface ----

type Client interface {
	CheckKVv2Mount(ctx context.Context, mount string) (bool, error)
	CheckAuthMount(ctx context.Context, mount string) (bool, error)
	EnableAuthMount(ctx context.Context, mount string, typ string) error

	UpsertPolicy(ctx context.Context, name, rules string) error
	GetPolicy(ctx context.Context, name string) (string, error)

	UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec) error
	GetK8sRole(ctx context.Context, authMount, roleName string) (*K8sRole, error)
}

type K8sRoleSpec struct {
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string // e.g. "1h"
	TokenMaxTTL                   string // e.g. "4h"
	Renewable                     *bool
}

type K8sRole struct {
	Name                          string
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string
	TokenMaxTTL                   string
	Renewable                     *bool
}

// ---- HTTP client (Vault/OpenBao HTTP API) ----

type httpClient struct {
	base  string // e.g. https://openbao.example:8200
	token string
	hc    *http.Client
}

func NewHTTPClient(baseURL, token string) Client {
	return &httpClient{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{},
	}
}

func (c *httpClient) authReq(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set(hdrVaultToken, c.token)
	if body != nil {
		req.Header.Set(hdrContentType, ctJSON)
	}
	return req, nil
}

func (c *httpClient) do(req *http.Request) ([]byte, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close() // errcheck: explicitly ignore close error
	}()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bao %s %s: %s", req.Method, req.URL.Path, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// CheckAuthMount returns true if an auth mount with the given path exists and is type "kubernetes".
func (c *httpClient) CheckAuthMount(ctx context.Context, mount string) (bool, error) {
	// Normalize the target key once (accept with/without trailing slash)
	want := strings.Trim(mount, "/")

	req, err := c.authReq(ctx, http.MethodGet, pathSysAuth, nil)
	if err != nil {
		return false, err
	}
	data, err := c.do(req)
	if err != nil {
		return false, err
	}

	type mnt struct {
		Type string `json:"type"`
	}

	// The response can be either wrapped ({ "data": { ... } }) or flat (map[string]mount).
	// Try wrapped first.
	var wrapped struct {
		Data map[string]mnt `json:"data"`
	}
	var maps map[string]mnt

	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Data != nil {
		maps = wrapped.Data
	} else {
		// Fallback: flat map
		var flat map[string]mnt
		if err2 := json.Unmarshal(data, &flat); err2 != nil {
			return false, err // return the original unmarshal error for context
		}
		maps = flat
	}

	// First try direct lookup using both key variants.
	if m, ok := maps[want+"/"]; ok && m.Type == authTypeKubernetes {
		return true, nil
	}
	if m, ok := maps[want]; ok && m.Type == authTypeKubernetes {
		return true, nil
	}

	// As a final guard, scan and normalize keys; some servers differ on trailing slash handling.
	for k, m := range maps {
		if strings.Trim(k, "/") == want && m.Type == authTypeKubernetes {
			return true, nil
		}
	}
	return false, nil
}

// --- Mounts: verify KV v2 ---

// GET /v1/sys/mounts and check that <mount>/ exists with type=kv and options.version=2.
func (c *httpClient) CheckKVv2Mount(ctx context.Context, mount string) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	req, err := c.authReq(ctx, http.MethodGet, pathSysMounts, nil)
	if err != nil {
		return false, err
	}
	data, err := c.do(req)
	if err != nil {
		return false, err
	}
	var resp struct {
		Data map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	// OpenBao/Vault returns a flat object; try both shapes to be safe.
	if err := json.Unmarshal(data, &resp); err != nil {
		var flat map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		}
		if err2 := json.Unmarshal(data, &flat); err2 != nil {
			return false, err
		}
		resp.Data = flat
	}
	m, ok := resp.Data[mount]
	if !ok {
		return false, nil
	}
	return m.Type == kvType && m.Options != nil && m.Options["version"] == kvVersionV2, nil
}

// EnableAuthMount enables an auth method at /sys/auth/<mount> with the given type.
// Succeeds idempotently: if the server returns 400 with "already in use", this returns nil.
func (c *httpClient) EnableAuthMount(ctx context.Context, mount string, typ string) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return fmt.Errorf("mount path is empty")
	}
	if typ == "" {
		return fmt.Errorf("auth type is empty")
	}

	body := map[string]any{"type": typ}
	req, err := c.authReq(ctx, "POST", "/v1/sys/auth/"+mount, body)
	if err != nil {
		return err
	}

	// We need access to status code and body to treat specific 4xx as success.
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	msg := strings.ToLower(string(b))
	// Vault/OpenBao commonly returns 400 with a message like "path is already in use" when the mount exists.
	if resp.StatusCode == http.StatusBadRequest &&
		(strings.Contains(msg, "already in use") || strings.Contains(msg, "path is already in use")) {
		return nil
	}

	return fmt.Errorf("bao %s %s: %s", req.Method, req.URL.Path, strings.TrimSpace(string(b)))
}

// --- Policies ---

// PUT /v1/sys/policies/acl/:name  with {"policy": "<rules>"}
func (c *httpClient) UpsertPolicy(ctx context.Context, name, rules string) error {
	body := map[string]string{"policy": rules}
	req, err := c.authReq(ctx, http.MethodPut, pathPolicyPrefix+name, body)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

func (c *httpClient) GetPolicy(ctx context.Context, name string) (string, error) {
	req, err := c.authReq(ctx, http.MethodGet, pathPolicyPrefix+name, nil)
	if err != nil {
		return "", err
	}
	b, err := c.do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Data struct {
			Rules string `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	return out.Data.Rules, nil
}

// --- Kubernetes auth roles ---

// POST /v1/auth/<mount>/role/<roleName>
// Fields: token_policies, bound_service_account_names, bound_service_account_namespaces, token_ttl, token_max_ttl, token_renewable
func (c *httpClient) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec) error {
	authMount = strings.Trim(authMount, "/")
	body := map[string]any{
		"token_policies":                   spec.Policies,
		"bound_service_account_names":      spec.BoundServiceAccountNames,
		"bound_service_account_namespaces": spec.BoundServiceAccountNamespaces,
	}
	if spec.TokenTTL != "" {
		body["token_ttl"] = spec.TokenTTL
	}
	if spec.TokenMaxTTL != "" {
		body["token_max_ttl"] = spec.TokenMaxTTL
	}
	if spec.Renewable != nil {
		body["token_renewable"] = *spec.Renewable
	}

	req, err := c.authReq(ctx, http.MethodPost, fmt.Sprintf(pathAuthRoleFormat, authMount, roleName), body)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

func (c *httpClient) GetK8sRole(ctx context.Context, authMount, roleName string) (*K8sRole, error) {
	authMount = strings.Trim(authMount, "/")
	req, err := c.authReq(ctx, http.MethodGet, fmt.Sprintf(pathAuthRoleFormat, authMount, roleName), nil)
	if err != nil {
		return nil, err
	}
	b, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Name      string   `json:"name"`
			Policies  []string `json:"token_policies"`
			BoundSANs []string `json:"bound_service_account_names"`
			BoundNS   []string `json:"bound_service_account_namespaces"`
			TokenTTL  string   `json:"token_ttl"`
			TokenMax  string   `json:"token_max_ttl"`
			Renewable *bool    `json:"token_renewable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &K8sRole{
		Name:                          out.Data.Name,
		Policies:                      out.Data.Policies,
		BoundServiceAccountNames:      out.Data.BoundSANs,
		BoundServiceAccountNamespaces: out.Data.BoundNS,
		TokenTTL:                      out.Data.TokenTTL,
		TokenMaxTTL:                   out.Data.TokenMax,
		Renewable:                     out.Data.Renewable,
	}, nil
}
