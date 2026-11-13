package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXraySubscriptionSkipsOnlyReferencedBalancers(t *testing.T) {
	const outbound = `"outbounds":[{"tag":"node","protocol":"hysteria","settings":{}}]`
	const balancer = `"balancers":[{"tag":"pool"}]`
	body := `[
		{"remarks":"Used",` + outbound + `,"routing":{` + balancer + `,"rules":[{"balancerTag":"pool"}]}},
		{"remarks":"Unused",` + outbound + `,"routing":{` + balancer + `,"rules":[{"outboundTag":"node"}]}},
		{"remarks":"Unknown reference",` + outbound + `,"routing":{` + balancer + `,"rules":[{"balancerTag":"other"}]}}
	]`
	entries, err := parseXraySubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	assertDeepEqual(t, names, []string{"Unused", "Unknown reference"})
}

func TestXrayJSONSubscriptionPreservesOutbounds(t *testing.T) {
	const hysteria = `{
		"tag": "proxy",
		"protocol": "hysteria",
		"settings": {"address":"192.0.2.10","port":443,"version":2},
		"streamSettings": {
			"network":"hysteria","security":"tls",
			"hysteriaSettings":{"auth":"test-auth","version":2},
			"tlsSettings":{"alpn":["h3"],"fingerprint":"firefox","serverName":"front.example","verifyPeerCertByName":"origin.example"},
			"finalmask":{"quicParams":{"congestion":"bbr","debug":false,"keepAlivePeriod":20,"maxIdleTimeout":60,"maxIncomingStreams":1024}}
		}
	}`
	const xhttp = `{
		"tag":"proxy",
		"protocol":"vless",
		"settings":{"vnext":[{"address":"192.0.2.11","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},
		"streamSettings":{
			"network":"xhttp","security":"reality",
			"realitySettings":{"fingerprint":"firefox","serverName":"example.com"},
			"xhttpSettings":{"extra":{"xmux":{"cMaxReuseTimes":0},"futureParam":9007199254740993}},
			"sockopt":{"tcpKeepAliveIdle":300}
		}
	}`
	body := `[
		{"remarks":"🇯🇵 Япония - Игровой","outbounds":[` + hysteria + `,{"tag":"direct","protocol":"freedom"}]},
		{"remarks":"Япония","inbounds":[{}],"routing":{},"outbounds":[` + xhttp + `,{"tag":"block","protocol":"blackhole"}]},
		{"remarks":"hy2","outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[]}}]}
	]`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.UserAgent(); got != "XKeen-Subscription-Watcher" {
			t.Errorf("unexpected User-Agent: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	dir := t.TempDir()
	if err := runMain(t, "--output-dir", dir, "--no-restart", "--protocol-tags",
		"--dialer-proxies=upstream", "--reality-fingerprint=chrome", "resist="+server.URL); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "04_outbounds.resist.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	outbounds := result["outbounds"].([]any)
	if len(result) != 1 || len(outbounds) != 6 {
		t.Fatalf("expected only 3 server outbounds and their dialer variants, got %s", data)
	}
	var wantHysteria, wantXHTTP map[string]any
	for raw, target := range map[string]*map[string]any{hysteria: &wantHysteria, xhttp: &wantXHTTP} {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(target); err != nil {
			t.Fatal(err)
		}
	}
	wantHysteria["tag"] = "resist--hy2--🇯🇵 Япония - Игровой"
	assertDeepEqual(t, outbounds[0], wantHysteria)
	wantXHTTP["tag"] = "resist--xhttp--Япония"
	stream := wantXHTTP["streamSettings"].(map[string]any)
	stream["realitySettings"].(map[string]any)["fingerprint"] = "chrome"
	assertDeepEqual(t, outbounds[2], wantXHTTP)
	wantXHTTP["tag"] = "resist--xhttp--Япония--upstream"
	stream["sockopt"].(map[string]any)["dialerProxy"] = "upstream"
	assertDeepEqual(t, outbounds[3], wantXHTTP)
	assertDeepEqual(t, outbounds[4].(map[string]any)["tag"], "resist--other--hy2")
}

func TestEmptyOrMalformedSubscriptionPreservesConfig(t *testing.T) {
	server := newTestServer(map[string]testResponse{
		"/valid":     {body: `{"outbounds":[{"tag":"node","protocol":"hysteria","settings":{"version":2}}]}`},
		"/empty":     {body: `[]`},
		"/malformed": {body: `[{"outbounds":[{"protocol":"hysteria"}]}]`},
		"/broken":    {body: `[{"outbounds":`},
		"/html":      {body: `<html>Subscription unavailable</html>`},
	})
	defer server.Close()

	dir := t.TempDir()
	if err := runMain(t, "--no-restart", "--output-dir", dir, "resist="+server.URL+"/valid"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "04_outbounds.resist.json")
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/empty", "/malformed", "/broken", "/html"} {
		t.Run(endpoint, func(t *testing.T) {
			if err := runMain(t, "--no-restart", "--output-dir", dir, "resist="+server.URL+endpoint); err == nil {
				t.Fatal("expected update to fail")
			}
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(current) != string(previous) {
				t.Fatal("existing configuration changed")
			}
		})
	}
}

func TestHysteria2URIOptions(t *testing.T) {
	const pin = "abababababababababababababababababababababababababababababababab"
	body := "hy2://user:pass%3Aword@[2001:db8::1]:443,5000-5010/?obfs=gecko&obfs-password=example&pinSHA256=" + pin +
		"&insecure=1&ech=dGVzdA%3D%3D&sni=front.example&verifyPeerCertByName=origin.example&fp=firefox&alpn=h3#HY2"
	server := newTestServer(map[string]testResponse{"/sub": {body: encodeSubscription(body)}})
	defer server.Close()

	dir := t.TempDir()
	if err := runMain(t, "--no-restart", "--output-dir", dir, "--protocol-tags", "resist="+server.URL+"/sub"); err != nil {
		t.Fatal(err)
	}
	config := loadConfig(t, dir, "resist")
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	assertDeepEqual(t, outbound["tag"], "resist--hy2--HY2")
	assertDeepEqual(t, outbound["settings"], map[string]any{"address": "2001:db8::1", "port": float64(443), "version": float64(2)})
	stream := outbound["streamSettings"].(map[string]any)
	assertDeepEqual(t, stream["hysteriaSettings"], map[string]any{"auth": "user:pass:word", "version": float64(2)})
	assertDeepEqual(t, stream["tlsSettings"], map[string]any{
		"serverName": "front.example", "verifyPeerCertByName": "origin.example", "allowInsecure": false,
		"pinnedPeerCertSha256": pin, "echConfigList": "dGVzdA==", "fingerprint": "firefox", "alpn": []any{"h3"},
	})
	assertDeepEqual(t, stream["finalmask"], map[string]any{
		"quicParams": map[string]any{"udpHop": map[string]any{"ports": "443,5000-5010"}},
		"udp":        []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": "example", "packetSize": "512-1200"}}},
	})
}
