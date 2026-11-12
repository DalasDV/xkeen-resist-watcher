package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
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
	name             string
	outbounds        []map[string]any
	primary          profileBalancer
	backup           profileBalancer
	burstObservatory json.RawMessage
}

func findManagedProfiles(profiles []xrayProfile) []managedProfile {
	var result []managedProfile
	for _, profile := range profiles {
		if managed, ok := compileManagedProfile(profile); ok {
			result = append(result, managed)
		}
	}
	return result
}

func ordinaryManagedProfile(entries []subscriptionOutbound) (managedProfile, error) {
	compiled := managedProfile{
		name: "Серверы подписки",
		primary: profileBalancer{
			Tag:      managedPrimary,
			Strategy: json.RawMessage(`{"type":"leastPing"}`),
		},
	}
	counts := make(map[string]int)
	seen := make(map[string]bool)
	for _, entry := range entries {
		config := maps.Clone(entry.config)
		delete(config, "tag")
		identity, err := json.Marshal(config)
		if err != nil {
			return managedProfile{}, err
		}
		if seen[string(identity)] {
			continue
		}
		seen[string(identity)] = true
		prefix := managedOther
		stream, _ := entry.config["streamSettings"].(map[string]any)
		switch stream["network"] {
		case "hysteria":
			prefix = managedHysteria
		case "xhttp", "splithttp":
			prefix = managedXHTTP
		}
		if counts[prefix] == 0 {
			compiled.primary.Selector = append(compiled.primary.Selector, prefix)
		}
		counts[prefix]++
		config["tag"] = fmt.Sprintf("%s%d", prefix, counts[prefix])
		compiled.outbounds = append(compiled.outbounds, config)
	}
	if len(compiled.outbounds) == 0 {
		return managedProfile{}, fmt.Errorf("в подписке нет поддерживаемых серверов")
	}
	return compiled, nil
}

func compileManagedProfile(profile xrayProfile) (managedProfile, bool) {
	var routing struct {
		Balancers []profileBalancer `json:"balancers"`
		Rules     []struct {
			InboundTag  []string `json:"inboundTag"`
			BalancerTag string   `json:"balancerTag"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(profile.Routing, &routing); err != nil {
		return managedProfile{}, false
	}
	for _, primary := range routing.Balancers {
		inbound := findLoopbackInbound(profile.Outbounds, primary.FallbackTag)
		if inbound == "" || !usesLeastPing(primary) {
			continue
		}
		for _, rule := range routing.Rules {
			if !slices.Contains(rule.InboundTag, inbound) {
				continue
			}
			for _, backup := range routing.Balancers {
				if backup.Tag != rule.BalancerTag || backup.Tag == primary.Tag || !usesLeastPing(backup) ||
					(backup.FallbackTag != "" && backup.FallbackTag != "direct") {
					continue
				}
				hy2, ok := collectManagedPool(profile.Outbounds, primary.Selector, managedHysteria, "hysteria")
				if !ok {
					continue
				}
				xhttp, ok := collectManagedPool(profile.Outbounds, backup.Selector, managedXHTTP, "xhttp")
				if !ok || len(hy2)+len(xhttp) == 0 {
					continue
				}
				primary.Tag = managedPrimary
				primary.Selector = []string{managedHysteria}
				primary.FallbackTag = managedLoopback
				backup.Tag = managedBackup
				backup.Selector = []string{managedXHTTP}
				name := profile.Remarks
				if name == "" {
					name = "Автобалансировка"
				}
				return managedProfile{
					name:             name,
					outbounds:        append(append(hy2, xhttp...), managedLoopbackConfig()),
					primary:          primary,
					backup:           backup,
					burstObservatory: profile.BurstObservatory,
				}, true
			}
		}
	}
	return managedProfile{}, false
}

func usesLeastPing(balancer profileBalancer) bool {
	var strategy struct {
		Type string `json:"type"`
	}
	return len(balancer.Selector) != 0 && json.Unmarshal(balancer.Strategy, &strategy) == nil &&
		strings.EqualFold(strategy.Type, "leastPing")
}

func findLoopbackInbound(outbounds []map[string]any, tag string) string {
	for _, outbound := range outbounds {
		if outbound["tag"] == tag && outbound["protocol"] == "loopback" {
			settings, _ := outbound["settings"].(map[string]any)
			inbound, _ := settings["inboundTag"].(string)
			return inbound
		}
	}
	return ""
}

func collectManagedPool(outbounds []map[string]any, selectors []string, prefix, transport string) ([]map[string]any, bool) {
	var result []map[string]any
	for _, outbound := range outbounds {
		tag, _ := outbound["tag"].(string)
		if !slices.ContainsFunc(selectors, func(selector string) bool {
			return selector != "" && strings.HasPrefix(tag, selector)
		}) {
			continue
		}
		stream, _ := outbound["streamSettings"].(map[string]any)
		network, _ := stream["network"].(string)
		sockopt, _ := stream["sockopt"].(map[string]any)
		proxySettings, _ := outbound["proxySettings"].(map[string]any)
		if network != transport && !(transport == "xhttp" && network == "splithttp") ||
			transport == "hysteria" && outbound["protocol"] != "hysteria" ||
			sockopt["dialerProxy"] != nil || proxySettings["tag"] != nil {
			return nil, false
		}
		config := maps.Clone(outbound)
		config["tag"] = fmt.Sprintf("%s%d", prefix, len(result)+1)
		result = append(result, config)
	}
	return result, true
}

func managedLoopbackConfig() map[string]any {
	return map[string]any{
		"tag":      managedLoopback,
		"protocol": "loopback",
		"settings": map[string]any{"inboundTag": managedFallbackIn},
	}
}
