package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

const managedFeed = `[
	{
	  "remarks":"Example Auto",
	  "outbounds":[
	    {"tag":"udp-east","protocol":"hysteria","settings":{"version":2,"address":"192.0.2.10","port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com","verifyPeerCertByName":"origin.example"},"hysteriaSettings":{"version":2,"auth":"test"},"finalmask":{"quicParams":{"congestion":"bbr","keepAlivePeriod":20}}}},
	    {"tag":"udp-west","protocol":"hysteria","settings":{"version":2,"address":"192.0.2.11","port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com"},"hysteriaSettings":{"version":2,"auth":"test"}}},
	    {"tag":"tcp-first","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.12","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/test"}}},
	    {"tag":"next","protocol":"loopback","settings":{"inboundTag":"retry"}},
	    {"tag":"direct","protocol":"freedom"}
	  ],
	  "routing":{"rules":[{"type":"field","inboundTag":["retry"],"balancerTag":"tcp"},{"type":"field","network":"tcp,udp","balancerTag":"udp"}],
	    "balancers":[{"tag":"udp","selector":["udp-"],"strategy":{"type":"leastPing"},"fallbackTag":"next"},
	                 {"tag":"tcp","selector":["tcp-"],"strategy":{"type":"leastPing"},"fallbackTag":"direct"}]},
	  "burstObservatory":{"subjectSelector":["udp-","tcp-"],"pingConfig":{"interval":"20s","sampling":1,"timeout":"5s","destination":"https://example.com/probe"}}
	},
	{"remarks":"🇯🇵 Япония - Игровой","outbounds":[{"tag":"udp-east","protocol":"hysteria","settings":{"version":2,"address":"192.0.2.10","port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com","verifyPeerCertByName":"origin.example"},"hysteriaSettings":{"version":2,"auth":"test"},"finalmask":{"quicParams":{"congestion":"bbr","keepAlivePeriod":20}}}}]},
	{"remarks":"Нидерланды 1","outbounds":[{"tag":"tcp-first","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.12","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/test"}}}]}
]`

func TestManagedSubscriptionImportsNamedNodes(t *testing.T) {
	profile, err := compileManagedSubscription(managedFeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.outbounds) != 3 {
		t.Fatalf("expected two individual nodes and local loopback, got %d outbounds", len(profile.outbounds))
	}
	assertDeepEqual(t, profile.primary.Selector, []string{"hy2-"})
	assertDeepEqual(t, profile.backup.Selector, []string{"xhttp-"})
	for i, tag := range []string{"hy2-🇯🇵 Япония - Игровой", "xhttp-Нидерланды 1", managedLoopback} {
		assertDeepEqual(t, profile.outbounds[i]["tag"], tag)
	}
	stream := profile.outbounds[0]["streamSettings"].(map[string]any)
	if stream["finalmask"] == nil || stream["tlsSettings"].(map[string]any)["verifyPeerCertByName"] != "origin.example" {
		t.Fatal("transport or TLS settings lost")
	}
	profiles, err := decodeXrayProfiles(managedFeed)
	if err != nil {
		t.Fatal(err)
	}
	balancerOnly, err := json.Marshal(profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileManagedSubscription(string(balancerOnly)); err == nil {
		t.Fatal("a subscription with only an upstream balancer must fail")
	}
}

func TestNamedOutboundsSurviveReordering(t *testing.T) {
	entries, err := parseXraySubscription(managedFeed)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, subscriptionOutbound{
		name:   entries[0].name,
		config: map[string]any{"protocol": "hysteria", "settings": map[string]any{"address": "192.0.2.20"}},
	})
	first, err := ordinaryManagedProfile(entries)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(entries)
	second, err := ordinaryManagedProfile(entries)
	if err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, first.outbounds, second.outbounds)
}

func TestMigrateOutboundRules(t *testing.T) {
	profile, err := compileManagedSubscription(managedFeed)
	if err != nil {
		t.Fatal(err)
	}
	rule := jsonObject{"outboundTag": "hy2-5"}
	doc := jsonObject{"routing": jsonObject{"rules": []any{rule}}}
	old := configureOutbound(profile.outbounds[0], "hy2-5", "", "")
	if err := migrateOutboundRules(doc, []jsonObject{old}, profile.outbounds); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, rule["outboundTag"], "hy2-🇯🇵 Япония - Игровой")

	rule["outboundTag"] = "hy2-5"
	if err := migrateOutboundRules(doc, []jsonObject{old}, profile.outbounds[1:]); err == nil {
		t.Fatal("expected error for a missing replacement")
	}
	assertDeepEqual(t, rule["outboundTag"], "hy2-5")
}

func TestSetupForOrdinarySubscription(t *testing.T) {
	body := "hy2://test@hy.example.com#Hysteria\nvless://00000000-0000-4000-8000-000000000001@x.example.com?type=xhttp#XHTTP"
	profile, err := compileManagedSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, profile.primary.Selector, []string{"hy2-"})
	assertDeepEqual(t, profile.backup.Selector, []string{"xhttp-"})
	routing, err := decodeXrayObject([]byte(`{"routing":{"rules":[{"type":"field","balancerTag":"proxy","network":"tcp,udp"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := configureManagedRouting(routing, nil, profile); err != nil {
		t.Fatal(err)
	}
	burst := routing["burstObservatory"].(map[string]any)
	if _, ok := burst["pingConfig"].(map[string]any); !ok {
		t.Fatal("ordinary subscriptions need a valid burstObservatory.pingConfig")
	}
}

func TestManagedCronMigratesOnlyMatchingJob(t *testing.T) {
	content := "# retain\n15 * * * * /opt/sbin/xkeen-subscription-watcher 'custom=https://example.com/sub'\n30 * * * * /opt/sbin/xkeen-subscription-watcher other=https://example.com/other\n"
	got, tag, err := prepareManagedCron([]byte(content), "https://example.com/sub", "")
	if err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, tag, "custom")
	expected := strings.Replace(content, "'custom=https://example.com/sub'", "refresh", 1)
	assertDeepEqual(t, string(got), expected)
}

func TestManagedSetupRefreshWithXray(t *testing.T) {
	xray := os.Getenv("XKEEN_TEST_XRAY")
	if xray == "" {
		t.Skip("set XKEEN_TEST_XRAY to run against the real Xray executable")
	}
	root := t.TempDir()
	paths := managedPaths{configDir: filepath.Join(root, "configs"), stateDir: filepath.Join(root, "state")}
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{paths.configDir, bin} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(xray, filepath.Join(bin, "xray")); err != nil {
		t.Fatal(err)
	}
	cron, log, fail := filepath.Join(root, "cron"), filepath.Join(root, "restart.log"), filepath.Join(root, "fail")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_CRON", cron)
	t.Setenv("TEST_RESTART", log)
	t.Setenv("TEST_FAIL", fail)
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write(filepath.Join(bin, "crontab"), `#!/bin/sh
case "$1" in
  -l) cat "$TEST_CRON";;
  -) cat > "$TEST_CRON";;
  *) exit 2;;
esac
`, 0700)
	write(filepath.Join(bin, "xkeen"), `#!/bin/sh
[ "$1" = "-restart" ] || exit 2
echo restart >> "$TEST_RESTART"
if [ -e "$TEST_FAIL" ]; then rm "$TEST_FAIL"; exit 1; fi
`, 0700)
	write(filepath.Join(paths.configDir, "04_outbounds.json"), `{
		"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"existing-node","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.8","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]}}]
	}`, 0600)
	routePath := filepath.Join(paths.configDir, "05_routing.json")
	initialRoute := `{
		// XKeen policies
		"routing":{"domainStrategy":"AsIs","rules":[
			{"type":"field","domain":["domain:local.example"],"outboundTag":"direct"},
			{"type":"field","network":"tcp,udp","balancerTag":"old-vpn"}
		],"balancers":[
			{"tag":"old-vpn","selector":["existing-node"],"strategy":{"type":"random"}},
			{"tag":"unused-old","selector":["existing-node"],"strategy":{"type":"random"}}
		]}
	}`
	write(routePath, initialRoute, 0600)
	const legacyObservatory = `{"observatory":{"subjectSelector":["existing-node"],"probeURL":"http://legacy.example.com/204","probeInterval":"30s"}}`
	observerPath := filepath.Join(paths.configDir, "07_observatory.json")
	write(observerPath, legacyObservatory, 0600)
	write(filepath.Join(paths.configDir, "03_inbounds.json"), `{"inbounds":[]}`, 0600)
	write(filepath.Join(paths.configDir, "config-notes.txt"), "backup me", 0600)

	var response atomic.Value
	response.Store(managedFeed)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hwid, err := os.ReadFile(filepath.Join(paths.stateDir, "hwid"))
		if err != nil || r.Header.Get("X-Hwid") != strings.TrimSpace(string(hwid)) || len(r.Header.Get("X-Hwid")) != 64 {
			t.Error("subscription request must carry the persisted HWID")
		}
		requests.Add(1)
		io.WriteString(w, response.Load().(string))
	}))
	defer server.Close()
	var messages bytes.Buffer
	if err := paths.update(server.URL, modeBalance, &messages); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(messages.String(), "setup") || !strings.Contains(messages.String(), "XKeen перезапущен.") || strings.Contains(messages.String(), server.URL) {
		t.Fatal("setup instructions missing or URL was shown")
	}
	state := filepath.Join(paths.stateDir, managedStateName)
	if info, err := os.Stat(state); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file was not saved: %v", err)
	}
	var saved managedSubscription
	if err := json.Unmarshal(read(state), &saved); err != nil || saved.Tag != "watcher" || saved.Mode != modeBalance {
		t.Fatalf("setup did not save the profile: %v", err)
	}
	if string(read(cron)) != "0 * * * * "+watcherPath+" refresh\n" {
		t.Fatal("unexpected cron entry")
	}
	initialOutput := read(filepath.Join(paths.configDir, "04_outbounds.watcher.json"))
	if bytes.Count(initialOutput, []byte(`"tag":`)) != 3 {
		t.Fatal("expected one Hysteria, one XHTTP and loopback")
	}
	got := string(read(routePath))
	for _, want := range []string{"local.example", managedFallbackIn, "http://legacy.example.com/204", `"balancerTag": "old-vpn"`, `"tag": "old-vpn"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("routing missing %q", want)
		}
	}
	if strings.Contains(got, "unused-old") || strings.Contains(got, `"type": "random"`) ||
		strings.Contains(string(read(observerPath)), `"observatory"`) {
		t.Fatal("old balancers or observatory survived")
	}
	backupRoot := filepath.Join(paths.configDir, "watcher-backup")
	snapshots, err := os.ReadDir(backupRoot)
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("expected one snapshot: %v", err)
	}
	snapshot := filepath.Join(backupRoot, snapshots[0].Name())
	assertDeepEqual(t, string(read(filepath.Join(snapshot, "05_routing.json"))), initialRoute)
	assertDeepEqual(t, string(read(filepath.Join(snapshot, "07_observatory.json"))), legacyObservatory)
	assertDeepEqual(t, string(read(filepath.Join(snapshot, "03_inbounds.json"))), `{"inbounds":[]}`)
	assertDeepEqual(t, string(read(filepath.Join(snapshot, "config-notes.txt"))), "backup me")

	if err := paths.update("", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, string(read(log)), "restart\n")
	assertDeepEqual(t, requests.Load(), int32(2))
	outputPath := filepath.Join(paths.configDir, "04_outbounds.watcher.json")
	response.Store(strings.ReplaceAll(managedFeed, "192.0.2.10", "192.0.2.15"))
	write(fail, "", 0600)
	if err := paths.update("", "", io.Discard); err == nil {
		t.Fatal("expected restart to fail")
	}
	assertDeepEqual(t, read(outputPath), initialOutput)
	if err := paths.update("", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(read(outputPath), []byte("192.0.2.15")) {
		t.Fatal("new server was not applied")
	}

	const namedTag = "hy2-🇯🇵 Япония - Игровой"
	write(outputPath, strings.Replace(string(read(outputPath)), namedTag, "hy2-5", 1), 0600)
	routing := strings.Replace(string(read(routePath)), `"rules": [`, `"rules": [
		{"type":"field","sourceIP":["192.168.1.99"],"outboundTag":"hy2-5"},`, 1)
	routing = strings.Replace(routing, "http://legacy.example.com/204", "http://probe.example.com/204", 1)
	write(routePath, routing, 0600)
	write(state, strings.Replace(string(read(state)), "{", `{"profile":"Example Auto",`, 1), 0600)
	if err := paths.update("", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	got = string(read(routePath))
	if !strings.Contains(got, `"outboundTag": "`+namedTag+`"`) || !strings.Contains(got, "http://probe.example.com/204") {
		t.Fatal("refresh did not migrate the fixed outbound or preserve the local probe")
	}

	legacyOutput := filepath.Join(paths.configDir, "04_outbounds.resist.json")
	expected := read(outputPath)
	if err := os.Rename(outputPath, legacyOutput); err != nil {
		t.Fatal(err)
	}
	legacyState := strings.Replace(string(read(state)), `"tag": "watcher"`, `"tag": "resist"`, 1)
	write(state, legacyState, 0600)
	write(outputPath, "another configuration", 0600)
	if err := paths.update("", "", io.Discard); err == nil || !strings.Contains(err.Error(), "уже существуют") {
		t.Fatalf("expected a filename conflict, got %v", err)
	}
	assertDeepEqual(t, string(read(outputPath)), "another configuration")
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	write(fail, "", 0600)
	if err := paths.update("", "", io.Discard); err == nil {
		t.Fatal("expected rollback after restart failure during rename")
	}
	assertDeepEqual(t, read(legacyOutput), expected)
	assertDeepEqual(t, string(read(state)), legacyState)
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("new file should be removed during rollback: %v", err)
	}
	if err := paths.update("", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, read(outputPath), expected)
	if _, err := os.Stat(legacyOutput); !os.IsNotExist(err) {
		t.Fatalf("legacy file should be removed after migration: %v", err)
	}
	if err := json.Unmarshal(read(state), &saved); err != nil || saved.Tag != "watcher" {
		t.Fatalf("expected saved watcher tag: %v", err)
	}
	snapshots, err = os.ReadDir(backupRoot)
	if err != nil || len(snapshots) != 3 {
		t.Fatalf("expected snapshots before both migration attempts: %v", err)
	}

	restarts := read(log)
	before := read(routePath)
	messages.Reset()
	if err := paths.update(server.URL, modeOutbounds, &messages); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, read(routePath), before)
	assertDeepEqual(t, read(log), restarts)
	if strings.Contains(string(read(outputPath)), managedLoopback) || strings.Contains(messages.String(), "XKeen перезапущен.") {
		t.Fatal("nodes-only mode generated a loopback or restarted XKeen")
	}
	snapshots, err = os.ReadDir(backupRoot)
	if err != nil || len(snapshots) != 4 {
		t.Fatalf("expected separate backups after rerunning setup: %v", err)
	}
	response.Store(strings.ReplaceAll(managedFeed, "192.0.2.10", "192.0.2.16"))
	if err := paths.update("", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, read(routePath), before)
	assertDeepEqual(t, read(log), restarts)
	if !bytes.Contains(read(outputPath), []byte("192.0.2.16")) {
		t.Fatal("nodes-only refresh did not update nodes")
	}
}

func TestSetupMode(t *testing.T) {
	for input, want := range map[string]string{"1\n": modeBalance, "2\n": modeOutbounds, "\n": modeOutbounds, "wrong\n1\n": modeBalance} {
		mode, err := readSetupMode(bufio.NewReader(strings.NewReader(input)), io.Discard)
		if err != nil || mode != want {
			t.Fatalf("input %q: got %q, %v; want %q", input, mode, err, want)
		}
	}
}
