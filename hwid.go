package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func routerHWID() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	path := routerCommand("ndmc").Path
	if output, err := exec.CommandContext(ctx, path, "-c", "show defaults").Output(); err == nil {
		if serial := keeneticSerial(string(output)); serial != "" {
			return hardwareID("serial", serial)
		}
	}
	for _, path := range []string{
		"/sys/firmware/devicetree/base/serial-number",
		"/proc/device-tree/serial-number",
		"/sys/class/dmi/id/product_serial",
	} {
		if data, err := os.ReadFile(path); err == nil {
			if serial := usableSerial(string(data)); serial != "" {
				return hardwareID("serial", serial)
			}
		}
	}
	if mac := permanentEthernetMAC("/sys/class/net"); mac != "" {
		return hardwareID("mac", mac)
	}
	return ""
}

func keeneticSerial(defaults string) string {
	for _, line := range strings.Split(defaults, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "serial") {
			return usableSerial(value)
		}
	}
	return ""
}

func usableSerial(value string) string {
	serial := strings.ToLower(strings.Trim(strings.TrimSpace(value), "\x00"))
	switch serial {
	case "", "none", "unknown", "not specified", "not applicable", "default string", "system serial number", "to be filled by o.e.m.":
		return ""
	}
	if len(serial) < 4 || strings.Contains(serial, "*") || strings.Trim(serial, "0") == "" {
		return ""
	}
	return serial
}

func permanentEthernetMAC(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		device := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(device, "device")); err != nil {
			continue
		}
		kind, _ := os.ReadFile(filepath.Join(device, "type"))
		assignment, _ := os.ReadFile(filepath.Join(device, "addr_assign_type"))
		if strings.TrimSpace(string(kind)) != "1" || strings.TrimSpace(string(assignment)) != "0" {
			continue
		}
		address, _ := os.ReadFile(filepath.Join(device, "address"))
		mac, err := net.ParseMAC(strings.TrimSpace(string(address)))
		if err == nil && len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00" {
			return mac.String()
		}
	}
	return ""
}

func hardwareID(kind, identifier string) string {
	hash := sha256.Sum256([]byte("xkeen-subscription-watcher/hwid/v1\x00" + kind + "\x00" + identifier))
	return hex.EncodeToString(hash[:])
}
