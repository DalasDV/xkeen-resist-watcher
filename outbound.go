package main

import (
	"maps"
	"net/url"
)

// buildStreamSettings builds the streamSettings block shared by the TLS/transport
// family (vless, vmess, trojan).
func buildStreamSettings(sp streamParams, address string) map[string]any {
	ss := map[string]any{
		"network":  sp.network,
		"security": sp.security,
	}

	switch sp.security {
	case "reality":
		fingerprint := sp.fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		realitySettings := map[string]any{
			"serverName":  sp.serverName,
			"fingerprint": fingerprint,
			"publicKey":   sp.publicKey,
		}
		if sp.spiderX != "" {
			realitySettings["spiderX"] = sp.spiderX
		}
		if sp.shortID != "" {
			realitySettings["shortId"] = sp.shortID
		}
		ss["realitySettings"] = realitySettings

	case "tls":
		serverName := sp.serverName
		if serverName == "" {
			serverName = address
		}
		fingerprint := sp.fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		tlsSettings := map[string]any{
			"serverName":    serverName,
			"allowInsecure": sp.allowInsecure,
			"fingerprint":   fingerprint,
		}
		if len(sp.alpn) > 0 {
			tlsSettings["alpn"] = sp.alpn
		}
		ss["tlsSettings"] = tlsSettings
	}

	switch sp.network {
	case "ws":
		wsSettings := map[string]any{}
		if sp.path != "" {
			wsSettings["path"] = sp.path
		}
		if sp.host != "" {
			wsSettings["host"] = sp.host
		}
		if len(wsSettings) > 0 {
			ss["wsSettings"] = wsSettings
		}

	case "grpc":
		grpcSettings := map[string]any{}
		if sp.serviceName != "" {
			grpcSettings["serviceName"] = sp.serviceName
		}
		if sp.host != "" {
			grpcSettings["authority"] = sp.host
		}
		if sp.mode == "multi" {
			grpcSettings["multiMode"] = true
		}
		if len(grpcSettings) > 0 {
			ss["grpcSettings"] = grpcSettings
		}

	case "xhttp":
		xhttpSettings := map[string]any{}
		if sp.host != "" {
			xhttpSettings["host"] = sp.host
		}
		if sp.path != "" {
			if decoded, err := url.PathUnescape(sp.path); err == nil {
				xhttpSettings["path"] = decoded
			} else {
				xhttpSettings["path"] = sp.path
			}
		}
		if sp.mode != "" {
			xhttpSettings["mode"] = sp.mode
		}
		if len(xhttpSettings) > 0 {
			ss["xhttpSettings"] = xhttpSettings
		}
	}

	return ss
}

func generateOutbound(p proxy) map[string]any {
	var proxyConfig map[string]any

	switch p := p.(type) {
	case vlessProxy:
		proxyConfig = map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": p.address,
						"port":    p.port,
						"users": []any{
							map[string]any{
								"id":         p.userID,
								"encryption": p.encryption,
								"flow":       p.flow,
							},
						},
					},
				},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address),
		}

	case vmessProxy:
		proxyConfig = map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": p.address,
						"port":    p.port,
						"users": []any{
							map[string]any{
								"id":       p.userID,
								"alterId":  p.alterID,
								"security": p.security,
							},
						},
					},
				},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address),
		}

	case trojanProxy:
		server := map[string]any{
			"address":  p.address,
			"port":     p.port,
			"password": p.password,
		}
		if p.flow != "" {
			server["flow"] = p.flow
		}
		proxyConfig = map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{
				"servers": []any{server},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address),
		}

	case shadowSocksProxy:
		proxyConfig = map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"servers": []any{
					map[string]any{
						"address":  p.address,
						"port":     p.port,
						"method":   p.method,
						"password": p.password,
					},
				},
			},
		}

	case hysteria2Proxy:
		return p.outbound()

	default:
		panic("unreachable")
	}

	return proxyConfig
}

func protocolTag(prefix string, outbound map[string]any) string {
	if outbound["protocol"] == "hysteria" {
		return prefix + "--hy2"
	}
	stream, _ := outbound["streamSettings"].(map[string]any)
	switch stream["network"] {
	case "xhttp", "splithttp":
		return prefix + "--xhttp"
	default:
		return prefix + "--other"
	}
}

func configureOutbound(base map[string]any, tag, realityFingerprint, dialerProxy string) map[string]any {
	result := maps.Clone(base)
	result["tag"] = tag
	if realityFingerprint == "" && dialerProxy == "" {
		return result
	}

	stream, _ := base["streamSettings"].(map[string]any)
	stream = maps.Clone(stream)
	if reality, ok := stream["realitySettings"].(map[string]any); ok && realityFingerprint != "" {
		reality = maps.Clone(reality)
		reality["fingerprint"] = realityFingerprint
		stream["realitySettings"] = reality
	}
	if dialerProxy != "" {
		if stream == nil {
			stream = make(map[string]any)
		}
		sockopt, _ := stream["sockopt"].(map[string]any)
		sockopt = maps.Clone(sockopt)
		if sockopt == nil {
			sockopt = make(map[string]any)
		}
		sockopt["dialerProxy"] = dialerProxy
		stream["sockopt"] = sockopt
	}
	if stream != nil {
		result["streamSettings"] = stream
	}
	return result
}
