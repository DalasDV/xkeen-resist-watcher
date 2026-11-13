package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
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
		routing = jsonObject{}
		document["routing"] = routing
	}
	rules, _ := routing["rules"].([]any)
	var updatedRules []any
	if profile.backup.Tag != "" {
		updatedRules = append(updatedRules, jsonObject{
			"type":        "field",
			"inboundTag":  []string{managedFallbackIn},
			"balancerTag": managedBackup,
		})
	}

	referenced := make(map[string]bool)
	for _, entry := range rules {
		rule, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("некорректное правило Xray")
		}
		tags := jsonStrings(rule["inboundTag"])
		if rule["balancerTag"] == managedBackup && len(tags) == 1 &&
			(tags[0] == managedFallbackIn || tags[0] == "resist-xhttp-fallback") {
			continue
		}
		if tag, ok := rule["balancerTag"].(string); ok {
			referenced[tag] = true
		}
		updatedRules = append(updatedRules, rule)
	}
	if len(updatedRules) > 0 {
		routing["rules"] = updatedRules
	} else {
		delete(routing, "rules")
	}

	balancers := []any{profile.primary}
	if profile.backup.Tag != "" {
		balancers = append(balancers, profile.backup)
	}
	oldBalancers, _ := routing["balancers"].([]any)
	for _, entry := range oldBalancers {
		old, _ := entry.(map[string]any)
		tag, _ := old["tag"].(string)
		if !referenced[tag] || tag == managedPrimary || tag == profile.backup.Tag {
			continue
		}
		alias := profile.primary
		alias.Tag = tag
		balancers = append(balancers, alias)
		delete(referenced, tag)
	}
	routing["balancers"] = balancers

	ping := jsonObject{
		"destination": "https://connectivitycheck.gstatic.com/generate_204",
		"interval":    "20s",
		"sampling":    1,
		"timeout":     "5s",
	}
	if burst, ok := current["burstObservatory"].(map[string]any); ok {
		if existing, ok := burst["pingConfig"].(map[string]any); ok {
			ping = maps.Clone(existing)
			for _, field := range []string{"interval", "timeout"} {
				if duration := xrayDuration(ping[field]); duration != "" {
					ping[field] = duration
				}
			}
		}
	} else if observatory, ok := current["observatory"].(map[string]any); ok {
		if destination, ok := observatory["probeURL"].(string); ok && destination != "" {
			ping["destination"] = destination
		}
		if interval := xrayDuration(observatory["probeInterval"]); interval != "" {
			ping["interval"] = interval
		}
	}
	delete(document, "observatory")
	document["burstObservatory"] = jsonObject{
		"subjectSelector": append(slices.Clone(profile.primary.Selector), profile.backup.Selector...),
		"pingConfig":      ping,
	}
	return nil
}

func xrayDuration(value any) string {
	switch duration := value.(type) {
	case string:
		return duration
	case json.Number:
		// Xray -dump may represent durations as nanoseconds, including scientific notation.
		if nanos, err := duration.Int64(); err == nil {
			return time.Duration(nanos).String()
		}
		if nanos, err := duration.Float64(); err == nil && nanos >= 0 && nanos < 1<<63 {
			return time.Duration(nanos).String()
		}
	}
	return ""
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

type xrayConfigFile struct {
	original routerFile
	document jsonObject
}

func isXrayConfig(name string) bool {
	switch filepath.Ext(name) {
	case ".json", ".jsonc", ".yaml", ".yml", ".toml":
		return true
	}
	return false
}

func (p managedPaths) loadXrayConfigs() ([]xrayConfigFile, int, error) {
	entries, err := os.ReadDir(p.configDir)
	if err != nil {
		return nil, -1, err
	}
	var files []xrayConfigFile
	activeRouting, defaultRouting := -1, -1
	for _, entry := range entries {
		if entry.IsDir() || !isXrayConfig(entry.Name()) {
			continue
		}
		file, err := readRouterFile(filepath.Join(p.configDir, entry.Name()))
		if err != nil {
			return nil, -1, err
		}
		document, err := decodeXrayObject(file.data)
		if !json.Valid(file.data) {
			document, err = p.dumpXray("-c", file.path)
		}
		if err != nil || document == nil {
			return nil, -1, fmt.Errorf("не удалось разобрать конфигурацию Xray в %s", file.path)
		}
		if entry.Name() == "05_routing.json" {
			defaultRouting = len(files)
		}
		if document["routing"] != nil {
			activeRouting = len(files)
		}
		files = append(files, xrayConfigFile{original: file, document: document})
	}
	if activeRouting == -1 {
		activeRouting = defaultRouting
		if activeRouting == -1 {
			activeRouting = len(files)
			files = append(files, xrayConfigFile{
				original: routerFile{path: filepath.Join(p.configDir, "05_routing.json")},
				document: jsonObject{},
			})
		}
	}
	return files, activeRouting, nil
}

func (p managedPaths) prepareXrayChanges(profile managedProfile, previousTag, tag string, balance bool) ([]routerChange, error) {
	outbounds, err := readRouterFile(filepath.Join(p.configDir, "04_outbounds."+tag+".json"))
	if err != nil {
		return nil, err
	}
	previousFile := outbounds
	var changes []routerChange
	if previousTag != tag {
		previousFile, err = readRouterFile(filepath.Join(p.configDir, "04_outbounds."+previousTag+".json"))
		if err != nil {
			return nil, err
		}
		if previousFile.exists {
			if outbounds.exists {
				return nil, fmt.Errorf("файлы %s и %s уже существуют; проверьте, какой принадлежит Watcher", previousFile.path, outbounds.path)
			}
			changes = append(changes, routerChange{before: previousFile, remove: true})
		}
	}
	if !balance {
		nodes := slices.DeleteFunc(slices.Clone(profile.outbounds), func(node jsonObject) bool {
			return node["protocol"] == "loopback"
		})
		return appendXrayChange(changes, outbounds, jsonObject{"outbounds": nodes})
	}

	current, err := p.dumpXray("-confdir", p.configDir)
	if err != nil {
		return nil, err
	}
	files, activeRouting, err := p.loadXrayConfigs()
	if err != nil {
		return nil, err
	}
	var previousOutbounds []jsonObject
	if previousFile.exists {
		previous, err := decodeXrayObject(previousFile.data)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать текущий файл выходов watcher")
		}
		previousOutbounds = outboundsFrom(previous)
	}
	proxies, err := managedOutbounds(current, previousOutbounds, profile)
	if err != nil {
		return nil, err
	}
	changes, err = appendXrayChange(changes, outbounds, jsonObject{"outbounds": proxies})
	if err != nil {
		return nil, err
	}
	for i, file := range files {
		if previousTag != tag && file.original.path == previousFile.path {
			continue
		}
		document := file.document
		if i == activeRouting {
			if err := configureManagedRouting(document, current, profile); err != nil {
				return nil, err
			}
			if err := migrateOutboundRules(document, previousOutbounds, proxies); err != nil {
				return nil, fmt.Errorf("%s: %w", file.original.path, err)
			}
		} else {
			routing, _ := document["routing"].(map[string]any)
			_, hasBalancers := routing["balancers"]
			_, hasObservatory := document["observatory"]
			_, hasBurst := document["burstObservatory"]
			if !hasBalancers && !hasObservatory && !hasBurst {
				continue
			}
			delete(routing, "balancers")
			delete(document, "observatory")
			delete(document, "burstObservatory")
		}
		changes, err = appendXrayChange(changes, file.original, document)
		if err != nil {
			return nil, err
		}
	}
	if len(changes) > 0 {
		if err := p.testXrayChanges(changes); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

func appendXrayChange(changes []routerChange, file routerFile, document jsonObject) ([]routerChange, error) {
	generated, err := encodeXrayObject(document)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(file.data, generated) {
		return changes, nil
	}
	if filepath.Ext(file.path) == ".toml" {
		return nil, fmt.Errorf("перенесите настройки балансировки и мониторинга из %s в JSON перед автоматической настройкой", file.path)
	}
	mode := os.FileMode(0600)
	if file.exists {
		mode = file.mode
	}
	return append(changes, routerChange{before: file, data: generated, mode: mode}), nil
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

func migrateOutboundRules(document jsonObject, previous, updated []jsonObject) error {
	oldByTag := make(map[string]jsonObject)
	newByTag := make(map[string]bool)
	for _, outbound := range previous {
		tag, _ := outbound["tag"].(string)
		oldByTag[tag] = outbound
	}
	for _, outbound := range updated {
		tag, _ := outbound["tag"].(string)
		newByTag[tag] = true
	}

	routing, _ := document["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	for _, entry := range rules {
		rule, _ := entry.(map[string]any)
		tag, _ := rule["outboundTag"].(string)
		old := oldByTag[tag]
		if tag == "" || old == nil || newByTag[tag] {
			continue
		}

		oldConfig := maps.Clone(old)
		delete(oldConfig, "tag")
		var matches []string
		for _, outbound := range updated {
			config := maps.Clone(outbound)
			delete(config, "tag")
			if reflect.DeepEqual(oldConfig, config) {
				matches = append(matches, outbound["tag"].(string))
			}
		}
		if len(matches) != 1 {
			return fmt.Errorf("не удалось однозначно сопоставить выход %q с нодой подписки; проверьте outboundTag в правиле Xray", tag)
		}
		rule["outboundTag"] = matches[0]
	}
	return nil
}

func managedOutbounds(current jsonObject, previous []jsonObject, profile managedProfile) ([]map[string]any, error) {
	owned := make(map[string]bool)
	for _, egress := range previous {
		tag, _ := egress["tag"].(string)
		owned[tag] = true
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
		if entry.IsDir() || !isXrayConfig(entry.Name()) {
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
		if err := change.apply(filepath.Join(stage, filepath.Base(change.before.path))); err != nil {
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
