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
	{"remarks":"Individual","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"version":2,"address":"192.0.2.10","port":443}}]}
]`

func TestSelectManagedProfile(t *testing.T) {
	profile, name, err := selectManagedProfile(managedFeed, "", bufio.NewReader(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Example Auto" || len(profile.outbounds) != 4 {
		t.Fatalf("wrong profile %q, %d outbounds", name, len(profile.outbounds))
	}
	assertDeepEqual(t, profile.primary.Selector, []string{"hy2-"})
	assertDeepEqual(t, profile.backup.Selector, []string{"xhttp-"})
	for i, tag := range []string{"hy2-1", "hy2-2", "xhttp-1", managedLoopback} {
		assertDeepEqual(t, profile.outbounds[i]["tag"], tag)
	}
	stream := profile.outbounds[0]["streamSettings"].(map[string]any)
	if stream["finalmask"] == nil || stream["tlsSettings"].(map[string]any)["verifyPeerCertByName"] != "origin.example" {
		t.Fatal("transport or TLS settings lost")
	}
	if _, _, err := selectManagedProfile(managedFeed, "renamed", nil, io.Discard); err == nil {
		t.Fatal("refresh silently changed the selected profile")
	}
}

func TestSetupForOrdinarySubscription(t *testing.T) {
	body := "hy2://test@hy.example.com#Hysteria\nvless://00000000-0000-4000-8000-000000000001@x.example.com?type=xhttp#XHTTP"
	profile, name, err := selectManagedProfile(body, "", bufio.NewReader(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, name, "")
	assertDeepEqual(t, profile.primary.Selector, []string{"hy2-", "xhttp-"})
	assertDeepEqual(t, profile.backup.Tag, "")
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
			{"type":"field","network":"tcp,udp","outboundTag":"existing-node"}
		]}
	}`
	write(routePath, initialRoute, 0600)

	var response atomic.Value
	response.Store(managedFeed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, response.Load().(string))
	}))
	defer server.Close()
	var messages bytes.Buffer
	if err := paths.update(server.URL, bufio.NewReader(strings.NewReader("")), &messages); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(messages.String(), "setup") || strings.Contains(messages.String(), server.URL) {
		t.Fatal("setup instructions missing or URL was shown")
	}
	state := filepath.Join(paths.stateDir, managedStateName)
	if info, err := os.Stat(state); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file was not saved: %v", err)
	}
	var saved managedSubscription
	if err := json.Unmarshal(read(state), &saved); err != nil || saved.Profile != "Example Auto" || saved.Tag != "watcher" {
		t.Fatalf("setup did not save the profile: %v", err)
	}
	if string(read(cron)) != "0 * * * * "+watcherPath+" refresh\n" {
		t.Fatal("unexpected cron entry")
	}
	initialOutput := read(filepath.Join(paths.configDir, "04_outbounds.watcher.json"))
	if bytes.Count(initialOutput, []byte(`"tag":`)) != 4 {
		t.Fatal("expected two Hysteria, one XHTTP and loopback")
	}
	if got := string(read(routePath)); !strings.Contains(got, "local.example") || !strings.Contains(got, managedFallbackIn) ||
		!strings.Contains(got, "https://example.com/probe") || !strings.Contains(got, `"balancerTag": "proxy"`) {
		t.Fatal("expected preserved policy and generated routing")
	}

	if err := paths.update("", nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, string(read(log)), "restart\n")
	outputPath := filepath.Join(paths.configDir, "04_outbounds.watcher.json")
	response.Store(strings.Replace(managedFeed, "192.0.2.11", "192.0.2.15", 1))
	write(fail, "", 0600)
	if err := paths.update("", nil, io.Discard); err == nil {
		t.Fatal("expected restart to fail")
	}
	assertDeepEqual(t, read(outputPath), initialOutput)
	if err := paths.update("", nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(read(outputPath), []byte("192.0.2.15")) {
		t.Fatal("new server was not applied")
	}
}
