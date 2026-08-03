package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type agentConfig struct {
	APIKey  string `json:"apiKey"`
	BaseURL string `json:"baseUrl"`
	Model   string `json:"model"`
}
type agentRequest struct {
	Provider string      `json:"provider"`
	Findings []Finding   `json:"findings"`
	Config   agentConfig `json:"config"`
}
type providerEnv struct{ key, baseURL, model string }

var providers = map[string]providerEnv{
	"openai": {"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"}, "deepseek": {"DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL"},
	"qwen": {"QWEN_API_KEY", "QWEN_BASE_URL", "QWEN_MODEL"}, "kimi": {"KIMI_API_KEY", "KIMI_BASE_URL", "KIMI_MODEL"}, "custom": {"CUSTOM_API_KEY", "CUSTOM_BASE_URL", "CUSTOM_MODEL"},
}

func configured(value, env string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(os.Getenv(env))
}
func validateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("invalid API base URL")
	}
	local := u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if u.User != nil || (u.Scheme != "https" && !local) {
		return nil, errors.New("remote APIs must use HTTPS; HTTP is allowed only for localhost")
	}
	return u, nil
}

func runAgent(input agentRequest) (string, error) {
	env, ok := providers[input.Provider]
	if !ok {
		return "", errors.New("unsupported provider")
	}
	key, baseURL, model := configured(input.Config.APIKey, env.key), configured(input.Config.BaseURL, env.baseURL), configured(input.Config.Model, env.model)
	if key == "" || baseURL == "" || model == "" {
		return "", errors.New("provider is not configured")
	}
	u, err := validateEndpoint(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/chat/completions"
	findings := input.Findings
	if len(findings) > 80 {
		findings = findings[:80]
	}
	evidence, _ := json.Marshal(findings)
	payload := map[string]any{"model": model, "temperature": 0.2, "messages": []map[string]string{
		{"role": "system", "content": "You are LogSleuth, a defensive incident investigation agent. Base every conclusion on supplied evidence and cite exact IP, time, request path, and rule category. Do not invent facts or provide exploit instructions. Respond in Chinese with: executive summary, attack sequence, evidence table, confidence and limitations, safe next investigation steps."},
		{"role": "user", "content": "Analyze these deterministic local findings as leads, not proof of compromise:\n" + string(evidence)},
	}}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 90 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("provider request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("provider rejected request with HTTP %d", response.StatusCode)
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&decoded); err != nil {
		return "", errors.New("invalid provider response")
	}
	if len(decoded.Choices) == 0 || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" {
		return "", errors.New("provider returned no analysis")
	}
	return decoded.Choices[0].Message.Content, nil
}
