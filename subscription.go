package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const subscriptionUserAgent = "XKeen-Subscription-Watcher"

func fetchSubscription(sub subscription) (string, error) {
	body, err := doHTTPRequest(sub.url, false)
	if err != nil {
		log.Printf("Не удалось получить подписку %q без прокси, пробуем с прокси: %v", sub.tag, err)
		body, err = doHTTPRequest(sub.url, true)
		if err != nil {
			return "", err
		}
	}

	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "\uFEFF")), nil
}

func doHTTPRequest(requestURL string, withProxy bool) (string, error) {
	var transport *http.Transport
	if withProxy {
		proxyURL, _ := url.Parse("http://127.0.0.1:8080")
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	} else {
		transport = &http.Transport{}
	}

	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("неверный URL подписки")
	}
	req.Header.Set("User-Agent", subscriptionUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось выполнить HTTP-запрос подписки")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

type subscriptionOutbound struct {
	name   string
	config map[string]any
}

type xrayProfile struct {
	Remarks          string           `json:"remarks"`
	Outbounds        []map[string]any `json:"outbounds"`
	Routing          json.RawMessage  `json:"routing"`
	BurstObservatory json.RawMessage  `json:"burstObservatory"`
}

func decodeXrayProfiles(body string) ([]xrayProfile, error) {
	if !json.Valid([]byte(body)) {
		return nil, fmt.Errorf("некорректный Xray JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var profiles []xrayProfile
	if strings.HasPrefix(body, "{") {
		var profile xrayProfile
		if err := decoder.Decode(&profile); err != nil {
			return nil, fmt.Errorf("некорректный профиль Xray JSON")
		}
		profiles = []xrayProfile{profile}
	} else if err := decoder.Decode(&profiles); err != nil {
		return nil, fmt.Errorf("некорректный список профилей Xray JSON")
	}
	return profiles, nil
}

func parseXraySubscription(body string) ([]subscriptionOutbound, error) {
	profiles, err := decodeXrayProfiles(body)
	if err != nil {
		return nil, err
	}
	var result []subscriptionOutbound
	for _, profile := range profiles {
		remarks := sanitizeProxyName(profile.Remarks)
		imported := 0
		for _, outbound := range profile.Outbounds {
			protocol, ok := outbound["protocol"].(string)
			if !ok || protocol == "" {
				return nil, fmt.Errorf("у выхода Xray JSON отсутствует protocol")
			}
			switch protocol {
			case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http", "wireguard", "masque":
				if _, ok := outbound["settings"].(map[string]any); !ok {
					return nil, fmt.Errorf("у серверного выхода Xray JSON отсутствует settings")
				}
			default:
				continue
			}

			name := remarks
			tag, _ := outbound["tag"].(string)
			if name == "" {
				name = sanitizeProxyName(tag)
			} else if imported > 0 && tag != "" {
				name += "--" + sanitizeProxyName(tag)
			}
			result = append(result, subscriptionOutbound{name: name, config: outbound})
			imported++
		}
	}
	return result, nil
}

func parseSubscriptionResponse(body string) []string {
	body = strings.TrimSpace(body)

	decoded, err := base64.StdEncoding.DecodeString(body)
	if err == nil {
		body = strings.TrimSpace(string(decoded))
	}

	var result []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "vless://") ||
			strings.HasPrefix(line, "vmess://") ||
			strings.HasPrefix(line, "trojan://") ||
			strings.HasPrefix(line, "ss://") ||
			strings.HasPrefix(line, "hysteria2://") ||
			strings.HasPrefix(line, "hy2://") {
			result = append(result, line)
		}
	}

	return result
}

func getProxyName(rawURL string) string {
	idx := strings.LastIndex(rawURL, "#")
	if idx < 0 {
		return ""
	}
	name, err := url.QueryUnescape(strings.TrimSpace(rawURL[idx+1:]))
	if err != nil {
		name = strings.TrimSpace(rawURL[idx+1:])
	}
	return sanitizeProxyName(name)
}

func sanitizeProxyName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == ' ' || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
