package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Keep the first usable ID even if the firmware later exposes a different source.
func loadHWID(stateDir string, detect func() string) (string, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return "", err
	}
	lock, err := os.OpenFile(filepath.Join(stateDir, "hwid.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, "hwid")
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		decoded, decodeErr := hex.DecodeString(id)
		if decodeErr != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("некорректный HWID в %s", path)
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	id := detect()
	if id == "" {
		var random [sha256.Size]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		id = hex.EncodeToString(random[:])
		log.Print("Аппаратный ID недоступен. Watcher создаёт постоянный локальный HWID.")
	}
	if err := replaceFile(path, []byte(id+"\n"), 0600); err != nil {
		return "", err
	}
	return id, nil
}

func routerHWID() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := routerCommand("ndmc").Path
	// KeeneticOS can put ndmc outside the PATH inherited by Entware cron.
	if path == "ndmc" {
		for _, candidate := range []string{"/bin/ndmc", "/usr/bin/ndmc"} {
			if executable, err := exec.LookPath(candidate); err == nil {
				path = executable
				break
			}
		}
	}
	defaults := readKeeneticDefaults(ctx, path)
	if serial := keeneticSerial(defaults); serial != "" {
		return hardwareID("serial", serial)
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
	if serviceTag := keeneticServiceTag(defaults); serviceTag != "" {
		return hardwareID("servicetag", serviceTag)
	}
	return ""
}

func readKeeneticDefaults(ctx context.Context, path string) string {
	// Like the shell pipeline, use complete fields from stdout even if ndmc exits with an error.
	output, err := exec.CommandContext(ctx, path, "-c", "show defaults").Output()
	if err != nil && ctx.Err() != nil {
		// A timeout can interrupt ndmc in the middle of printing an identifier.
		output = output[:strings.LastIndexByte(string(output), '\n')+1]
	}
	return string(output)
}

func keeneticSerial(defaults string) string {
	return usableSerial(keeneticDefault(defaults, "serial"))
}

func keeneticServiceTag(defaults string) string {
	tag := strings.ReplaceAll(keeneticDefault(defaults, "servicetag"), "-", "")
	if len(tag) != 15 || strings.Trim(tag, "0") == "" || strings.Trim(tag, "0123456789") != "" {
		return ""
	}
	return tag
}

func keeneticDefault(defaults, field string) string {
	for _, line := range strings.Split(defaults, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), field) {
			return strings.Trim(value, " \t\r\n\x00")
		}
	}
	return ""
}

func usableSerial(value string) string {
	serial := strings.ToLower(strings.Trim(value, " \t\r\n\x00"))
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
