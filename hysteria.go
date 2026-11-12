package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type hysteria2Proxy struct {
	address          string
	port             int
	auth             string
	sni              string
	insecure         bool
	certificatePin   string
	verifyCertByName string
	fingerprint      string
	alpn             []string
	ech              string
	obfs             string
	obfsPassword     string
	hopPorts         string
}

func (hysteria2Proxy) isProxy() {}

func parseHysteria2URL(rawURL string) (proxy, error) {
	link, hopPorts, err := extractHysteriaPortHops(rawURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" || u.User == nil {
		return nil, fmt.Errorf("Hysteria2 требует адрес и учётные данные")
	}
	auth := u.User.Username()
	if password, ok := u.User.Password(); ok {
		auth += ":" + password
	}
	if auth == "" {
		return nil, fmt.Errorf("Hysteria2 требует непустой auth")
	}

	port := 443
	if u.Port() != "" {
		port, err = parseHysteriaPort(u.Port())
		if err != nil {
			return nil, err
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("некорректные параметры Hysteria2")
	}
	insecure := query.Get("insecure")
	if insecure != "" && insecure != "0" && insecure != "1" {
		return nil, fmt.Errorf("insecure в Hysteria2 должен быть 0 или 1")
	}
	pin := strings.ReplaceAll(query.Get("pinSHA256"), ":", "")
	if pin != "" {
		hash, err := hex.DecodeString(pin)
		if err != nil || len(hash) != 32 {
			return nil, fmt.Errorf("некорректный pinSHA256 в Hysteria2")
		}
	}

	obfs := query.Get("obfs")
	obfsPassword := query.Get("obfs-password")
	switch obfs {
	case "":
	case "salamander", "gecko":
		if obfsPassword == "" {
			return nil, fmt.Errorf("для obfs в Hysteria2 требуется пароль")
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый obfs в Hysteria2")
	}

	return hysteria2Proxy{
		address:          u.Hostname(),
		port:             port,
		auth:             auth,
		sni:              queryDefault(query, "sni", u.Hostname()),
		insecure:         insecure == "1" && pin == "",
		certificatePin:   pin,
		verifyCertByName: query.Get("verifyPeerCertByName"),
		fingerprint:      query.Get("fp"),
		alpn:             splitCSV(query.Get("alpn")),
		ech:              query.Get("ech"),
		obfs:             obfs,
		obfsPassword:     obfsPassword,
		hopPorts:         hopPorts,
	}, nil
}

// net/url accepts numeric ports only. Extract the Hysteria port list before parsing.
func extractHysteriaPortHops(rawURL string) (string, string, error) {
	scheme, rest, _ := strings.Cut(rawURL, "://")
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	addressStart := strings.LastIndexByte(authority, '@') + 1
	address := authority[addressStart:]
	portSeparator := strings.LastIndexByte(address, ':')
	if portSeparator <= strings.LastIndexByte(address, ']') {
		return rawURL, "", nil
	}
	ports := address[portSeparator+1:]
	if !strings.ContainsAny(ports, ",-") {
		return rawURL, "", nil
	}

	firstPort := ""
	for _, segment := range strings.Split(ports, ",") {
		lower, upper, hasUpper := strings.Cut(segment, "-")
		start, err := parseHysteriaPort(lower)
		if err != nil {
			return "", "", err
		}
		if hasUpper {
			end, err := parseHysteriaPort(upper)
			if err != nil || end < start {
				return "", "", fmt.Errorf("некорректный диапазон портов Hysteria2")
			}
		}
		if firstPort == "" {
			firstPort = lower
		}
	}
	portStart := addressStart + portSeparator + 1
	return scheme + "://" + authority[:portStart] + firstPort + rest[authorityEnd:], ports, nil
}

func parseHysteriaPort(value string) (int, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("некорректный порт Hysteria2")
	}
	return int(port), nil
}

func (p hysteria2Proxy) outbound() map[string]any {
	tlsSettings := map[string]any{
		"serverName":    p.sni,
		"allowInsecure": p.insecure,
	}
	for key, value := range map[string]string{
		"pinnedPeerCertSha256": p.certificatePin,
		"verifyPeerCertByName": p.verifyCertByName,
		"fingerprint":          p.fingerprint,
		"echConfigList":        p.ech,
	} {
		if value != "" {
			tlsSettings[key] = value
		}
	}
	if len(p.alpn) > 0 {
		tlsSettings["alpn"] = p.alpn
	}

	stream := map[string]any{
		"network":     "hysteria",
		"security":    "tls",
		"tlsSettings": tlsSettings,
		"hysteriaSettings": map[string]any{
			"version": 2,
			"auth":    p.auth,
		},
	}
	finalmask := map[string]any{}
	if p.obfs != "" {
		settings := map[string]any{"password": p.obfsPassword}
		if p.obfs == "gecko" {
			settings["packetSize"] = "512-1200"
		}
		finalmask["udp"] = []any{map[string]any{"type": "salamander", "settings": settings}}
	}
	if p.hopPorts != "" {
		finalmask["quicParams"] = map[string]any{
			"udpHop": map[string]any{"ports": p.hopPorts},
		}
	}
	if len(finalmask) > 0 {
		stream["finalmask"] = finalmask
	}
	return map[string]any{
		"protocol": "hysteria",
		"settings": map[string]any{
			"version": 2,
			"address": p.address,
			"port":    p.port,
		},
		"streamSettings": stream,
	}
}
