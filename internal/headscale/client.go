// Package headscale calls Headscale via its gRPC-Gateway HTTP/REST API.
// This avoids the protoc + Go-stub generation needed for raw gRPC, while
// covering every management endpoint Headscale exposes.
//
// All requests carry an `Authorization: Bearer <api_key>` header.
package headscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
)

type Client struct {
	addr   string
	apiKey string
	hc     *http.Client
}

func New(cfg settings.Headscale) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkip, MinVersion: tls.VersionTLS12},
	}
	return &Client{
		addr:   strings.TrimRight(cfg.Address, "/"),
		apiKey: cfg.APIKey,
		hc:     &http.Client{Timeout: 10 * time.Second, Transport: tr},
	}
}

// User represents a Headscale user (subset of the API model we render in the UI).
type User struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"`
	CreatedAt string `json:"createdAt"`
}

type Node struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	GivenName  string   `json:"givenName"`
	User       User     `json:"user"`
	IPAddrs    []string `json:"ipAddresses"`
	LastSeen   string   `json:"lastSeen"`
	Online     bool     `json:"online"`
	Expiry     string   `json:"expiry,omitempty"`
	RegisterMe string   `json:"registerMethod,omitempty"`
	// Tags is the merged list of tags Headscale considers active on this node
	// (forced + advertised+valid). The 0.28 API exposes only this combined field.
	Tags []string `json:"tags,omitempty"`
}

type PreAuthKey struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	User       User     `json:"user"`
	Reusable   bool     `json:"reusable"`
	Ephemeral  bool     `json:"ephemeral"`
	Used       bool     `json:"used"`
	Expiration string   `json:"expiration,omitempty"`
	CreatedAt  string   `json:"createdAt"`
	ACLTags    []string `json:"aclTags,omitempty"`
}

// IsExpired returns true if the key's expiration is in the past.
// An empty Expiration string means "never expires".
func (k PreAuthKey) IsExpired() bool {
	if k.Expiration == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, k.Expiration)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	if c.addr == "" {
		return errors.New("headscale address not configured")
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, rdr)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("headscale %s %s: %s — %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Ping(ctx context.Context) error {
	// /api/v1/user is the simplest endpoint and confirms auth too.
	return c.request(ctx, http.MethodGet, "/api/v1/user", nil, nil)
}

// Users
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/v1/user", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

func (c *Client) CreateUser(ctx context.Context, name, email string) (*User, error) {
	body := map[string]any{"name": name}
	if email != "" {
		body["email"] = email
	}
	var resp struct {
		User User `json:"user"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/v1/user", body, &resp); err != nil {
		return nil, err
	}
	return &resp.User, nil
}

func (c *Client) DeleteUser(ctx context.Context, name string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/user/"+name, nil, nil)
}

func (c *Client) RenameUser(ctx context.Context, oldName, newName string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/user/"+oldName+"/rename/"+newName, nil, nil)
}

// Nodes
func (c *Client) ListNodes(ctx context.Context, user string) ([]Node, error) {
	path := "/api/v1/node"
	if user != "" {
		path += "?user=" + user
	}
	var resp struct {
		Nodes []Node `json:"nodes"`
	}
	if err := c.request(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Nodes, nil
}

func (c *Client) DeleteNode(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/node/"+id, nil, nil)
}

func (c *Client) ExpireNode(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/node/"+id+"/expire", nil, nil)
}

func (c *Client) RenameNode(ctx context.Context, id, newName string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/node/"+id+"/rename/"+newName, nil, nil)
}

// MoveNodeToUser changes the owning user of a node. The endpoint exists in
// Headscale's gRPC-Gateway even when not surfaced by the CLI.
func (c *Client) MoveNodeToUser(ctx context.Context, nodeID, newUser string) error {
	path := "/api/v1/node/" + nodeID + "/user?user=" + newUser
	return c.request(ctx, http.MethodPost, path, nil, nil)
}

// SetNodeTags replaces the forced (admin-applied) tag list on a node.
// Tags must be in the form "tag:name". Pass nil/empty to clear.
func (c *Client) SetNodeTags(ctx context.Context, id string, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	body := map[string]any{"tags": tags}
	return c.request(ctx, http.MethodPost, "/api/v1/node/"+id+"/tags", body, nil)
}

// Policy / ACLs

type Policy struct {
	Policy    string `json:"policy"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func (c *Client) GetPolicy(ctx context.Context) (*Policy, error) {
	var p Policy
	if err := c.request(ctx, http.MethodGet, "/api/v1/policy", nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) SetPolicy(ctx context.Context, hujson string) error {
	body := map[string]any{"policy": hujson}
	return c.request(ctx, http.MethodPut, "/api/v1/policy", body, nil)
}

// Pre-auth keys
func (c *Client) ListPreAuthKeys(ctx context.Context, user string) ([]PreAuthKey, error) {
	path := "/api/v1/preauthkey"
	if user != "" {
		path += "?user=" + user
	}
	var resp struct {
		PreAuthKeys []PreAuthKey `json:"preAuthKeys"`
	}
	if err := c.request(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.PreAuthKeys, nil
}

func (c *Client) CreatePreAuthKey(ctx context.Context, user string, reusable, ephemeral bool, aclTags []string, expirationISO string) (*PreAuthKey, error) {
	body := map[string]any{
		"user":      user,
		"reusable":  reusable,
		"ephemeral": ephemeral,
	}
	if len(aclTags) > 0 {
		body["aclTags"] = aclTags
	}
	if expirationISO != "" {
		body["expiration"] = expirationISO
	}
	var resp struct {
		PreAuthKey PreAuthKey `json:"preAuthKey"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/v1/preauthkey", body, &resp); err != nil {
		return nil, err
	}
	return &resp.PreAuthKey, nil
}

func (c *Client) ExpirePreAuthKey(ctx context.Context, user, key string) error {
	body := map[string]any{"user": user, "key": key}
	return c.request(ctx, http.MethodPost, "/api/v1/preauthkey/expire", body, nil)
}

// TestConnection performs an authenticated Ping with a short timeout.
// Returns nil on success.
func TestConnection(ctx context.Context, cfg settings.Headscale) error {
	if cfg.Address == "" {
		return errors.New("address is required")
	}
	if cfg.APIKey == "" {
		return errors.New("api_key is required")
	}
	c := New(cfg)
	dctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return c.Ping(dctx)
}
