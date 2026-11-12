package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type jsonObject = map[string]any

func decodeXrayObject(data []byte) (jsonObject, error) {
	var object jsonObject
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	return object, nil
}

func encodeXrayObject(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func configureManagedRouting(document, current jsonObject, profile managedProfile) error {
	routing, _ := document["routing"].(map[string]any)
	if routing == nil {
		return fmt.Errorf("в 05_routing.json не найден раздел routing")
	}
	rules, _ := routing["rules"].([]any)
	target, err := existingVPNTarget(rules, current)
	if err != nil {
		return err
	}

	fallback := jsonObject{
		"type":        "field",
		"inboundTag":  []string{managedFallbackIn},
		"balancerTag": managedBackup,
	}
	var updatedRules []any
	previouslyManagedBackup := false
	if profile.backup.Tag != "" {
		updatedRules = append(updatedRules, fallback)
	}
	for _, entry := range rules {
		rule, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("некорректное правило в 05_routing.json")
		}
		tags := jsonStrings(rule["inboundTag"])
		if rule["balancerTag"] == managedBackup && len(tags) == 1 &&
			(tags[0] == managedFallbackIn || tags[0] == "resist-xhttp-fallback") {
			previouslyManagedBackup = true
			continue
		}
		if rule["outboundTag"] == target {
			delete(rule, "outboundTag")
			rule["balancerTag"] = managedPrimary
		}
		if rule["balancerTag"] == target {
			rule["balancerTag"] = managedPrimary
		}
		updatedRules = append(updatedRules, rule)
	}
	routing["rules"] = updatedRules

	balancers, _ := routing["balancers"].([]any)
	updatedBalancers := []any{profile.primary}
	if profile.backup.Tag != "" {
		updatedBalancers = append(updatedBalancers, profile.backup)
	}
	for _, entry := range balancers {
		balancer, _ := entry.(map[string]any)
		switch balancer["tag"] {
		case managedPrimary:
			continue
		case managedBackup:
			if previouslyManagedBackup {
				continue
			}
			if profile.backup.Tag != "" {
				return fmt.Errorf("тег %q занят другим балансировщиком", managedBackup)
			}
		}
		updatedBalancers = append(updatedBalancers, entry)
	}
	routing["balancers"] = updatedBalancers

	observatory, _ := document["burstObservatory"].(map[string]any)
	if observatory == nil {
		observatory, _ = document["observatory"].(map[string]any)
	}
	if observatory == nil {
		if current["observatory"] != nil || current["burstObservatory"] != nil {
			return fmt.Errorf("наблюдение Xray настроено в другом файле. Мастер использует 05_routing.json")
		}
		observatory = jsonObject{}
		if len(profile.burstObservatory) != 0 {
			upstream, err := decodeXrayObject(profile.burstObservatory)
			if err != nil {
				return fmt.Errorf("некорректные параметры наблюдения в профиле")
			}
			if pingConfig, ok := upstream["pingConfig"]; ok {
				observatory["pingConfig"] = pingConfig
			}
		}
		document["burstObservatory"] = observatory
	}
	if burst, ok := document["burstObservatory"].(map[string]any); ok && burst["pingConfig"] == nil {
		burst["pingConfig"] = jsonObject{
			"destination": "https://connectivitycheck.gstatic.com/generate_204",
			"interval":    "20s",
			"sampling":    1,
			"timeout":     "5s",
		}
	}
	selectors := append(slices.Clone(profile.primary.Selector), profile.backup.Selector...)
	for _, selector := range jsonStrings(observatory["subjectSelector"]) {
		if selector != "resist" && selector != "resist--hy2" && selector != "resist--xhttp" &&
			selector != managedHysteria && selector != managedXHTTP && selector != managedOther &&
			!slices.Contains(selectors, selector) {
			selectors = append(selectors, selector)
		}
	}
	observatory["subjectSelector"] = selectors
	return nil
}

func existingVPNTarget(rules []any, config jsonObject) (string, error) {
	for _, entry := range rules {
		rule, _ := entry.(map[string]any)
		if rule["outboundTag"] == managedPrimary || rule["balancerTag"] == managedPrimary {
			return managedPrimary, nil
		}
	}

	outbounds, _ := config["outbounds"].([]any)
	fullRouting, _ := config["routing"].(map[string]any)
	balancers, _ := fullRouting["balancers"].([]any)
	var targets []string
	for _, entry := range rules {
		rule, _ := entry.(map[string]any)
		if tag, _ := rule["balancerTag"].(string); tag != "" && tag != managedBackup && !slices.Contains(targets, tag) {
			for _, entry := range balancers {
				balancer, _ := entry.(map[string]any)
				if balancer["tag"] == tag {
					targets = append(targets, tag)
					break
				}
			}
		}
		tag, _ := rule["outboundTag"].(string)
		if tag == "" || slices.Contains(targets, tag) {
			continue
		}
		if tag == "vless-reality" {
			// The default XKeen routing template can reference this tag before
			// a real proxy outbound has been configured.
			targets = append(targets, tag)
			continue
		}
		for _, entry := range outbounds {
			outbound, _ := entry.(map[string]any)
			if outbound["tag"] != tag {
				continue
			}
			switch outbound["protocol"] {
			case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque":
				targets = append(targets, tag)
			}
			break
		}
	}
	if len(targets) == 1 {
		return targets[0], nil
	}
	return "", fmt.Errorf("в 05_routing.json не удалось определить один существующий VPN-маршрут для подключения балансировщика")
}

func jsonStrings(value any) []string {
	items, _ := value.([]any)
	var strings []string
	for _, item := range items {
		if value, ok := item.(string); ok {
			strings = append(strings, value)
		}
	}
	return strings
}

func (p managedPaths) prepareXrayChanges(profile managedProfile, tag string) ([]routerChange, error) {
	path := filepath.Join(p.configDir, "05_routing.json")
	routing, err := readRouterFile(path)
	if err != nil {
		return nil, err
	}
	if !routing.exists {
		return nil, fmt.Errorf("на роутере не найден %s", path)
	}
	outbounds, err := readRouterFile(filepath.Join(p.configDir, "04_outbounds."+tag+".json"))
	if err != nil {
		return nil, err
	}

	current, err := p.dumpXray("-confdir", p.configDir)
	if err != nil {
		return nil, err
	}
	var document jsonObject
	if json.Valid(routing.data) {
		document, err = decodeXrayObject(routing.data)
	} else {
		document, err = p.dumpXray("-c", path)
	}
	if err != nil {
		return nil, err
	}
	if err := configureManagedRouting(document, current, profile); err != nil {
		return nil, err
	}
	proxies, err := managedOutbounds(current, outbounds, profile)
	if err != nil {
		return nil, err
	}
	generated, err := encodeXrayObject(jsonObject{"outbounds": proxies})
	if err != nil {
		return nil, err
	}
	route, err := encodeXrayObject(document)
	if err != nil {
		return nil, err
	}

	var changes []routerChange
	if !bytes.Equal(outbounds.data, generated) {
		mode := os.FileMode(0644)
		if outbounds.exists {
			mode = outbounds.mode
		}
		changes = append(changes, routerChange{before: outbounds, data: generated, mode: mode})
	}
	if !bytes.Equal(routing.data, route) {
		changes = append(changes, routerChange{before: routing, data: route, mode: routing.mode})
	}
	if len(changes) > 0 {
		if err := p.testXrayChanges(changes); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

func (p managedPaths) xrayCommand(args ...string) *exec.Cmd {
	command := routerCommand("xray", append([]string{"run"}, args...)...)
	if os.Getenv("XRAY_LOCATION_ASSET") == "" {
		assets := filepath.Join(filepath.Dir(p.configDir), "dat")
		if info, err := os.Stat(assets); err == nil && info.IsDir() {
			command.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
		}
	}
	return command
}

func (p managedPaths) dumpXray(args ...string) (jsonObject, error) {
	command := p.xrayCommand(append([]string{"-dump"}, args...)...)
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать конфигурацию Xray (%s): %w", strings.Join(args, " "), err)
	}
	document, err := decodeXrayObject(data)
	if err != nil || document == nil {
		return nil, fmt.Errorf("Xray вернул некорректный результат -dump")
	}
	return document, nil
}

func managedOutbounds(current jsonObject, old routerFile, profile managedProfile) ([]map[string]any, error) {
	owned := make(map[string]bool)
	if old.exists {
		// The old watcher file is also generated JSON, even when other XKeen files use JSONC.
		previous, err := decodeXrayObject(old.data)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать текущий файл выходов watcher")
		}
		for _, egress := range outboundsFrom(previous) {
			tag, _ := egress["tag"].(string)
			owned[tag] = true
		}
	}
	selectors := append(slices.Clone(profile.primary.Selector), profile.backup.Selector...)
	var direct bool
	for _, egress := range outboundsFrom(current) {
		tag, _ := egress["tag"].(string)
		if owned[tag] {
			continue
		}
		if tag == "direct" {
			direct = egress["protocol"] == "freedom"
			if !direct && profile.backup.FallbackTag == "direct" {
				return nil, fmt.Errorf("тег direct занят выходом другого типа")
			}
		}
		if tag == managedLoopback && profile.backup.Tag != "" || slices.ContainsFunc(selectors, func(prefix string) bool {
			return strings.HasPrefix(tag, prefix)
		}) {
			return nil, fmt.Errorf("тег %q из другого файла Xray конфликтует с балансировщиком watcher", tag)
		}
	}
	if !direct && profile.backup.FallbackTag == "direct" {
		return append(slices.Clone(profile.outbounds), jsonObject{"protocol": "freedom", "tag": "direct"}), nil
	}
	return profile.outbounds, nil
}

func outboundsFrom(document jsonObject) []jsonObject {
	var outbounds []jsonObject
	entries, _ := document["outbounds"].([]any)
	for _, entry := range entries {
		if outbound, ok := entry.(map[string]any); ok {
			outbounds = append(outbounds, outbound)
		}
	}
	return outbounds
}

func (p managedPaths) testXrayChanges(changes []routerChange) error {
	stage, err := os.MkdirTemp(p.stateDir, "xray-test.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	entries, err := os.ReadDir(p.configDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch filepath.Ext(entry.Name()) {
		case ".json", ".jsonc", ".yaml", ".yml", ".toml":
		default:
			continue
		}
		data, err := os.ReadFile(filepath.Join(p.configDir, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, entry.Name()), data, 0600); err != nil {
			return err
		}
	}
	for _, change := range changes {
		if err := os.WriteFile(filepath.Join(stage, filepath.Base(change.before.path)), change.data, 0600); err != nil {
			return err
		}
	}
	command := p.xrayCommand("-test", "-confdir", stage)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("Xray отклонил настройки: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	// Xray replaces the routing section when a later file defines its own routing.
	merged, err := p.dumpXray("-confdir", stage)
	if err != nil {
		return err
	}
	routing, _ := merged["routing"].(map[string]any)
	balancers, _ := routing["balancers"].([]any)
	rules, _ := routing["rules"].([]any)
	if len(balancers) == 0 || len(rules) == 0 {
		return fmt.Errorf("другой файл Xray перекрывает маршрутизацию из 05_routing.json")
	}
	primary, _ := balancers[0].(map[string]any)
	if primary["tag"] != managedPrimary || !slices.ContainsFunc(jsonStrings(primary["selector"]), func(selector string) bool {
		return selector == managedHysteria || selector == managedXHTTP || selector == managedOther
	}) {
		return fmt.Errorf("другой файл Xray перекрывает маршрутизацию из 05_routing.json")
	}
	return nil
}
