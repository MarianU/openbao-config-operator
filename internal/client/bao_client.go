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

// ---- Public interface ----

type Client interface {
	CheckKVv2Mount(ctx context.Context, mount string) (bool, error)
	CheckAuthMount(ctx context.Context, mount string) (bool, error)

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
	req.Header.Set("X-Vault-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *httpClient) do(req *http.Request, want2xx bool) ([]byte, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if want2xx && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return nil, fmt.Errorf("bao %s %s: %s", req.Method, req.URL.Path, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// CheckAuthMount returns true if an auth mount with the given path exists and is type "kubernetes".
func (c *httpClient) CheckAuthMount(ctx context.Context, mount string) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	req, err := c.authReq(ctx, "GET", "/v1/sys/auth", nil)
	if err != nil {
		return false, err
	}
	b, err := c.do(req, true)
	if err != nil {
		return false, err
	}

	var resp struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	// handle flat map too
	if err := json.Unmarshal(b, &resp); err != nil {
		var flat map[string]struct {
			Type string `json:"type"`
		}
		if err2 := json.Unmarshal(b, &flat); err2 != nil {
			return false, err
		}
		resp.Data = flat
	}
	m, ok := resp.Data[mount]
	return ok && m.Type == "kubernetes", nil
}

// --- Mounts: verify KV v2 ---

// GET /v1/sys/mounts and check that <mount>/ exists with type=kv and options.version=2.
func (c *httpClient) CheckKVv2Mount(ctx context.Context, mount string) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	req, err := c.authReq(ctx, "GET", "/v1/sys/mounts", nil)
	if err != nil {
		return false, err
	}
	data, err := c.do(req, true)
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
	return m.Type == "kv" && m.Options != nil && m.Options["version"] == "2", nil
}

// --- Policies ---

// PUT /v1/sys/policies/acl/:name  with {"policy": "<rules>"}
func (c *httpClient) UpsertPolicy(ctx context.Context, name, rules string) error {
	body := map[string]string{"policy": rules}
	req, err := c.authReq(ctx, "PUT", "/v1/sys/policies/acl/"+name, body)
	if err != nil {
		return err
	}
	_, err = c.do(req, true)
	return err
}

func (c *httpClient) GetPolicy(ctx context.Context, name string) (string, error) {
	req, err := c.authReq(ctx, "GET", "/v1/sys/policies/acl/"+name, nil)
	if err != nil {
		return "", err
	}
	b, err := c.do(req, true)
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

	req, err := c.authReq(ctx, "POST", fmt.Sprintf("/v1/auth/%s/role/%s", authMount, roleName), body)
	if err != nil {
		return err
	}
	_, err = c.do(req, true)
	return err
}

func (c *httpClient) GetK8sRole(ctx context.Context, authMount, roleName string) (*K8sRole, error) {
	authMount = strings.Trim(authMount, "/")
	req, err := c.authReq(ctx, "GET", fmt.Sprintf("/v1/auth/%s/role/%s", authMount, roleName), nil)
	if err != nil {
		return nil, err
	}
	b, err := c.do(req, true)
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
