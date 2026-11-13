package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const subscriptionUserAgent = "XKeen-Subscription-Watcher"

var (
	errHWIDRequired = errors.New("сервер подписки требует HWID, но не принял идентификатор устройства")
	errHWIDLimit    = errors.New("в подписке достигнут лимит устройств")
)

func fetchSubscription(sub subscription, detectHWID func() string) (string, error) {
	hwid := detectHWID()
	if hwid == "" {
		return "", fmt.Errorf("не удалось определить аппаратный HWID: серийный номер и постоянный MAC недоступны")
	}
	body, err := doHTTPRequest(sub.url, hwid, false)
	if errors.Is(err, errHWIDRequired) || errors.Is(err, errHWIDLimit) {
		return "", err
	}
	if err != nil {
		log.Printf("Не удалось получить подписку %q без прокси, пробуем с прокси: %v", sub.tag, err)
		body, err = doHTTPRequest(sub.url, hwid, true)
		if err != nil {
			return "", err
		}
	}

	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "\uFEFF")), nil
}

func doHTTPRequest(requestURL, hwid string, withProxy bool) (string, error) {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	if withProxy {
		proxyURL, _ := url.Parse("http://127.0.0.1:8080")
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	if os.Getenv("SSL_CERT_FILE") == "" && os.Getenv("SSL_CERT_DIR") == "" {
		if pem, err := os.ReadFile("/opt/etc/ssl/certs/ca-certificates.crt"); err == nil {
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			if roots.AppendCertsFromPEM(pem) {
				transport.TLSClientConfig = &tls.Config{RootCAs: roots}
			}
		}
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
	if hwid != "" {
		req.Header.Set("X-Hwid", hwid)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось выполнить HTTP-запрос подписки")
	}
	defer resp.Body.Close()
	if strings.EqualFold(resp.Header.Get("X-Hwid-Max-Devices-Reached"), "true") ||
		strings.EqualFold(resp.Header.Get("X-Hwid-Limit"), "true") {
		return "", errHWIDLimit
	}
	if strings.EqualFold(resp.Header.Get("X-Hwid-Not-Supported"), "true") {
		return "", errHWIDRequired
	}
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
	Remarks   string           `json:"remarks"`
	Outbounds []map[string]any `json:"outbounds"`
	Routing   json.RawMessage  `json:"routing"`
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
		var routing struct {
			Balancers []struct {
				Tag string `json:"tag"`
			} `json:"balancers"`
			Rules []struct {
				BalancerTag string `json:"balancerTag"`
			} `json:"rules"`
		}
		if len(profile.Routing) > 0 {
			if err := json.Unmarshal(profile.Routing, &routing); err != nil {
				return nil, fmt.Errorf("некорректный routing в профиле Xray JSON")
			}
		}
		balancerTags := make(map[string]bool, len(routing.Balancers))
		for _, balancer := range routing.Balancers {
			if balancer.Tag != "" {
				balancerTags[balancer.Tag] = true
			}
		}
		usesBalancer := false
		for _, rule := range routing.Rules {
			if balancerTags[rule.BalancerTag] {
				usesBalancer = true
				break
			}
		}
		if usesBalancer {
			continue
		}
		remarks := strings.TrimSpace(profile.Remarks)
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
				name = strings.TrimSpace(tag)
			} else if imported > 0 && tag != "" {
				name += "--" + strings.TrimSpace(tag)
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
	return strings.TrimSpace(name)
}
