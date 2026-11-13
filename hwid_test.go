package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestKeeneticDefaultsWithNonzeroExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ndmc")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'serial: SN-1234\\n'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, keeneticSerial(readKeeneticDefaults(context.Background(), path)), "sn-1234")
}

func TestHardwareID(t *testing.T) {
	serial := keeneticSerial("model: Keenetic\n serial: SN-1234\n")
	assertDeepEqual(t, serial, "sn-1234")
	assertDeepEqual(t, usableSerial(" SN-1234\x00\n"), serial)
	assertDeepEqual(t, keeneticSerial("serial: S1749WF***"), "")
	assertDeepEqual(t, keeneticServiceTag("servicetag: 123-456-789-012-345\r\n"), "123456789012345")
	assertDeepEqual(t, keeneticServiceTag("servicetag: 123456789012345"), "123456789012345")
	assertDeepEqual(t, keeneticServiceTag("servicetag: 123456789012***"), "")
	id := hardwareID("serial", serial)
	if len(id) != 64 || id != hardwareID("serial", usableSerial("sn-1234")) ||
		id == hardwareID("serial", "sn-1235") {
		t.Fatal("hardware identifiers should be stable, distinct and 64 characters")
	}
}

func TestHWIDPersistsAcrossSourceChanges(t *testing.T) {
	dir := t.TempDir()
	want := hardwareID("serial", "test-device")
	id, err := loadHWID(dir, func() string { return want })
	if err != nil || id != want {
		t.Fatalf("first HWID: %q, %v", id, err)
	}
	id, err = loadHWID(dir, func() string { t.Fatal("re-probed saved HWID"); return "" })
	if err != nil || id != want {
		t.Fatalf("saved HWID: %q, %v", id, err)
	}
}

func TestConcurrentHWIDFallback(t *testing.T) {
	dir := t.TempDir()
	var calls sync.WaitGroup
	results := make(chan string, 8)
	for range cap(results) {
		calls.Go(func() {
			id, err := loadHWID(dir, func() string { return "" })
			if err != nil {
				t.Error(err)
			}
			results <- id
		})
	}
	calls.Wait()
	close(results)
	want := <-results
	if len(want) != 64 {
		t.Fatalf("invalid fallback HWID: %q", want)
	}
	for id := range results {
		assertDeepEqual(t, id, want)
	}
	other, err := loadHWID(t.TempDir(), func() string { return "" })
	if err != nil || len(other) != 64 || other == want {
		t.Fatalf("expected distinct fallback for another installation: %v", err)
	}
}

func TestEverySubscriptionFetchSendsSavedHWID(t *testing.T) {
	dir := t.TempDir()
	want := hardwareID("serial", "test-device")
	if _, err := loadHWID(dir, func() string { return want }); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hwid") != want {
			t.Error("missing saved HWID on subscription request")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/subscription", http.StatusFound)
			return
		}
		w.Write([]byte("subscription"))
	}))
	defer server.Close()
	for range 2 {
		if body, err := fetchSubscription(subscription{tag: "test", url: server.URL + "/redirect"}, dir); err != nil || body != "subscription" {
			t.Fatalf("unexpected response: %q, %v", body, err)
		}
	}
}

func TestPermanentEthernetMAC(t *testing.T) {
	root := t.TempDir()
	for name, address := range map[string]string{
		"eth0": "24:01:02:03:04:05",
		"eth1": "24:01:02:03:04:06",
		"br0":  "24:01:02:03:04:07",
	} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if name != "br0" {
			if err := os.Mkdir(filepath.Join(dir, "device"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for file, data := range map[string]string{"type": "1", "addr_assign_type": "0", "address": address} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertDeepEqual(t, permanentEthernetMAC(root), "24:01:02:03:04:05")
	if err := os.WriteFile(filepath.Join(root, "eth0", "addr_assign_type"), []byte("3"), 0600); err != nil {
		t.Fatal(err)
	}
	assertDeepEqual(t, permanentEthernetMAC(root), "24:01:02:03:04:06")
}

func TestSubscriptionRequestSendsHWID(t *testing.T) {
	hwid := hardwareID("serial", "test-device")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hwid") != hwid || r.UserAgent() != subscriptionUserAgent {
			t.Error("request did not carry the expected HWID and User-Agent")
		}
		if r.URL.Path == "/limit" {
			w.Header().Set("X-Hwid-Max-Devices-Reached", "true")
			return
		}
		w.Write([]byte("subscription"))
	}))
	defer server.Close()

	if body, err := doHTTPRequest(server.URL, hwid, false); err != nil || body != "subscription" {
		t.Fatalf("unexpected response: %q, %v", body, err)
	}
	if _, err := doHTTPRequest(server.URL+"/limit", hwid, false); !errors.Is(err, errHWIDLimit) {
		t.Fatalf("expected a device limit error, got %v", err)
	}
}
