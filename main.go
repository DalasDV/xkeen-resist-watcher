package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := newRootCmd(routerPaths)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func newRootCmd(paths managedPaths) *cobra.Command {
	var (
		outputDir          string
		noRestart          bool
		singleProxy        bool
		protocolTags       bool
		realityFingerprint string
		dialerProxies      []string
	)

	cmd := &cobra.Command{
		Use:   "xkeen-subscription-watcher [flags] <tag>=<url> ...",
		Short: "Обработка подписок и генерация конфигураций для Xray",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildConfig(args, outputDir, !noRestart, singleProxy, realityFingerprint, dialerProxies)
			if err != nil {
				return err
			}
			cfg.protocolTags = protocolTags
			cfg.stateDir = paths.stateDir
			return execute(cfg)
		},
	}

	cmd.Flags().StringVar(&outputDir, "output-dir", "/opt/etc/xray/configs",
		"Каталог для сохранения сгенерированных конфигураций.")
	cmd.Flags().BoolVar(&noRestart, "no-restart", false,
		"Не перезапускать XKeen после обновления конфигураций.")
	cmd.Flags().BoolVar(&singleProxy, "single-proxy", false,
		"Брать только первый прокси из подписки и не добавлять имя к тегу.")
	cmd.Flags().BoolVar(&protocolTags, "protocol-tags", false,
		"Добавлять отдельные префиксы тегов для Hysteria2 и XHTTP.")
	cmd.Flags().StringVar(&realityFingerprint, "reality-fingerprint", "",
		"Переопределить fingerprint для Reality подключений.")
	cmd.Flags().StringSliceVar(&dialerProxies, "dialer-proxies", nil,
		"Dialer proxies через запятую.")

	cmd.AddCommand(newVersionCmd(), paths.newSetupCmd(), paths.newRefreshCmd())

	return cmd
}

func getVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), getVersion())
			return err
		},
	}
}

type config struct {
	stateDir           string
	subscriptions      []subscription
	outputDir          string
	restartXkeen       bool
	dialerProxies      []string
	singleProxy        bool
	protocolTags       bool
	realityFingerprint string
}

type subscription struct {
	tag string
	url string
}

func buildConfig(
	positionalArgs []string,
	outputDir string,
	restartXkeen, singleProxy bool,
	realityFingerprint string,
	dialerProxies []string,
) (config, error) {
	if len(positionalArgs) == 0 {
		return config{}, fmt.Errorf("не указаны подписки. Использование: xkeen-subscription-watcher [флаги] <tag>=<url> ...")
	}

	var subs []subscription
	tags := make(map[string]bool)
	for _, arg := range positionalArgs {
		tag, u, found := strings.Cut(arg, "=")
		if !found {
			return config{}, fmt.Errorf("неверный формат подписки: %q, ожидается <tag>=<url>", arg)
		}
		if tags[tag] {
			return config{}, fmt.Errorf("тег %q указан несколько раз, используйте уникальные имена", tag)
		}
		tags[tag] = true
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return config{}, fmt.Errorf("неизвестный формат URL: %s, URL должен начинаться на http:// или https://", u)
		}
		subs = append(subs, subscription{tag: tag, url: u})
	}

	info, err := os.Stat(outputDir)
	if err != nil || !info.IsDir() {
		return config{}, fmt.Errorf("указанный путь для --output-dir %s не является директорией", outputDir)
	}

	return config{
		subscriptions:      subs,
		outputDir:          outputDir,
		restartXkeen:       restartXkeen,
		dialerProxies:      dialerProxies,
		singleProxy:        singleProxy,
		realityFingerprint: realityFingerprint,
	}, nil
}

func execute(cfg config) error {
	updated := false
	var failures []error
	for _, sub := range cfg.subscriptions {
		changed, err := processSubscription(sub, cfg)
		if err != nil {
			log.Printf("Ошибка при обработке подписки %q, пропускаем: %v", sub.tag, err)
			failures = append(failures, err)
			continue
		}
		if changed {
			updated = true
		}
	}

	if len(failures) == len(cfg.subscriptions) {
		return errors.Join(failures...)
	}
	if !updated {
		log.Println("Изменений в подписках не найдено, завершаем работу.")
		return nil
	}

	if cfg.restartXkeen {
		log.Println("Перезапускаем XKeen.")
		cmd := exec.Command("xkeen", "-restart")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	return nil
}

func processSubscription(sub subscription, cfg config) (bool, error) {
	outputPath := filepath.Join(cfg.outputDir, fmt.Sprintf("04_outbounds.%s.json", sub.tag))

	outbounds, err := getOutbounds(sub, cfg)
	if err != nil {
		return false, err
	}

	xrayConfig := map[string]any{
		"outbounds": outbounds,
	}

	newContent, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return false, fmt.Errorf("ошибка сериализации JSON: %w", err)
	}
	newContent = append(newContent, '\n')

	existingContent, err := os.ReadFile(outputPath)
	if err == nil && bytes.Equal(existingContent, newContent) {
		log.Printf("Изменения в подписке %q не найдены, пропускаем.", sub.tag)
		return false, nil
	}

	log.Printf("Записываем новую конфигурацию для подписки %q в %s.", sub.tag, outputPath)
	if err := replaceOutboundFile(outputPath, newContent); err != nil {
		return false, fmt.Errorf("ошибка записи файла %s: %w", outputPath, err)
	}

	return true, nil
}

func replaceOutboundFile(path string, content []byte) error {
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return replaceFile(path, content, mode)
}

func replaceFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".outbounds-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(content)
	chmodErr := file.Chmod(mode)
	closeErr := file.Close()
	if err := errors.Join(writeErr, chmodErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func getOutbounds(sub subscription, cfg config) ([]any, error) {
	body, err := fetchSubscription(sub, cfg.stateDir)
	if err != nil {
		return nil, err
	}
	var entries []subscriptionOutbound
	if strings.HasPrefix(body, "[") || strings.HasPrefix(body, "{") {
		log.Printf("Подписка %q: Xray JSON.", sub.tag)
		entries, err = parseXraySubscription(body)
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("Подписка %q: список ссылок.", sub.tag)
		entries = parseLinkOutbounds(body, sub.tag, cfg.singleProxy)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("в подписке %q нет серверных выходов", sub.tag)
	}

	usedTags := make(map[string]bool)
	var result []any
	for _, entry := range entries {
		baseTag := sub.tag
		if cfg.protocolTags {
			baseTag = protocolTag(baseTag, entry.config)
		}
		if !cfg.singleProxy && entry.name != "" {
			baseTag += "--" + entry.name
		}
		tag := reserveOutboundTag(usedTags, baseTag)
		result = append(result, configureOutbound(entry.config, tag, cfg.realityFingerprint, ""))
		for _, dialer := range cfg.dialerProxies {
			dialerTag := reserveOutboundTag(usedTags, tag+"--"+dialer)
			result = append(result, configureOutbound(entry.config, dialerTag, cfg.realityFingerprint, dialer))
		}
		if cfg.singleProxy {
			break
		}
	}
	return result, nil
}

func reserveOutboundTag(used map[string]bool, base string) string {
	tag := base
	for suffix := 2; used[tag]; suffix++ {
		tag = fmt.Sprintf("%s--%d", base, suffix)
	}
	used[tag] = true
	return tag
}

func parseLinkOutbounds(body, subscriptionTag string, singleProxy bool) []subscriptionOutbound {
	proxyURLs := parseSubscriptionResponse(body)
	sort.Strings(proxyURLs)
	var result []subscriptionOutbound
	for index, proxyURL := range proxyURLs {
		p, err := parseProxyURL(proxyURL)
		if err != nil {
			log.Printf("Не удалось разобрать прокси №%d из подписки %q, пропускаем.", index+1, subscriptionTag)
			continue
		}
		result = append(result, subscriptionOutbound{
			name:   getProxyName(proxyURL),
			config: generateOutbound(p),
		})
		if singleProxy {
			break
		}
	}
	return result
}
