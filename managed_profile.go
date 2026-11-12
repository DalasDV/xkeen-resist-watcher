package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

const (
	managedTag        = "watcher"
	managedPrimary    = "proxy"
	managedBackup     = "proxy-xhttp"
	managedLoopback   = "watcher-to-xhttp"
	managedFallbackIn = "watcher-xhttp-fallback"
	managedHysteria   = "hy2-"
	managedXHTTP      = "xhttp-"
	managedOther      = "proxy-"
)

type profileBalancer struct {
	Tag         string          `json:"tag"`
	Selector    []string        `json:"selector"`
	Strategy    json.RawMessage `json:"strategy"`
	FallbackTag string          `json:"fallbackTag,omitempty"`
}

type managedProfile struct {
	outbounds []map[string]any
	primary   profileBalancer
	backup    profileBalancer
}

func ordinaryManagedProfile(entries []subscriptionOutbound) (managedProfile, error) {
	leastPing := json.RawMessage(`{"type":"leastPing"}`)
	compiled := managedProfile{
		primary: profileBalancer{Tag: managedPrimary, Strategy: leastPing},
	}
	type namedOutbound struct {
		base string
		hash [32]byte
		data map[string]any
	}
	var named []namedOutbound
	counts := make(map[string]int)
	prefixes := make(map[string]bool)
	seen := make(map[string]map[[32]byte]bool)
	for _, entry := range entries {
		data := maps.Clone(entry.config)
		delete(data, "tag")
		identity, err := json.Marshal(data)
		if err != nil {
			return managedProfile{}, err
		}
		hash := sha256.Sum256(identity)
		prefix := managedOther
		stream, _ := data["streamSettings"].(map[string]any)
		switch network, _ := stream["network"].(string); {
		case network == "hysteria" || data["protocol"] == "hysteria":
			prefix = managedHysteria
		case network == "xhttp" || network == "splithttp":
			prefix = managedXHTTP
		}
		name := entry.name
		if name == "" {
			name = fmt.Sprintf("без-имени-%x", hash[:8])
		}
		base := prefix + name
		if seen[base] == nil {
			seen[base] = make(map[[32]byte]bool)
		}
		if seen[base][hash] {
			continue
		}
		seen[base][hash] = true
		prefixes[prefix] = true
		counts[base]++
		named = append(named, namedOutbound{base: base, hash: hash, data: data})
	}
	if len(named) == 0 {
		return managedProfile{}, fmt.Errorf("в подписке нет отдельных серверных выходов")
	}
	for _, entry := range named {
		tag := entry.base
		if counts[tag] > 1 {
			for suffix := 8; ; suffix += 2 {
				tag = fmt.Sprintf("%s [%x]", entry.base, entry.hash[:suffix])
				if counts[tag] == 0 {
					break
				}
				if suffix == len(entry.hash) {
					return managedProfile{}, fmt.Errorf("конфликт тегов выходов для %q", entry.base)
				}
			}
			counts[tag] = 1
		}
		entry.data["tag"] = tag
		compiled.outbounds = append(compiled.outbounds, entry.data)
	}
	slices.SortFunc(compiled.outbounds, func(a, b map[string]any) int {
		return cmp.Compare(a["tag"].(string), b["tag"].(string))
	})

	for _, prefix := range []string{managedHysteria, managedXHTTP, managedOther} {
		if prefixes[prefix] {
			compiled.primary.Selector = append(compiled.primary.Selector, prefix)
		}
	}
	if prefixes[managedHysteria] && prefixes[managedXHTTP] {
		compiled.backup = profileBalancer{
			Tag:         managedBackup,
			Selector:    slices.Clone(compiled.primary.Selector[1:]),
			Strategy:    leastPing,
			FallbackTag: "direct",
		}
		compiled.primary.Selector = []string{managedHysteria}
		compiled.primary.FallbackTag = managedLoopback
		compiled.outbounds = append(compiled.outbounds, map[string]any{
			"tag":      managedLoopback,
			"protocol": "loopback",
			"settings": map[string]any{"inboundTag": managedFallbackIn},
		})
	}
	return compiled, nil
}
