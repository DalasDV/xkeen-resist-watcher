package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const (
	managedStateName = "subscription.json"
	modeBalance      = "balance"
	modeOutbounds    = "outbounds"
)

type managedSubscription struct {
	URL  string `json:"url"`
	Tag  string `json:"tag"`
	Mode string `json:"mode"`
}

type managedPaths struct {
	configDir  string
	stateDir   string
	detectHWID func() string
}

var routerPaths = managedPaths{
	configDir:  "/opt/etc/xray/configs",
	stateDir:   "/opt/etc/xkeen-subscription-watcher",
	detectHWID: routerHWID,
}

func (p managedPaths) newSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Настроить или заменить подписку на роутере",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			in := bufio.NewReader(cmd.InOrStdin())
			out := cmd.OutOrStdout()
			fmt.Fprint(out, "Вставьте ссылку подписки и нажмите Enter: ")
			address, err := readSetupLine(in)
			if err != nil {
				return err
			}
			if address == "" {
				fmt.Fprintln(out, "Чтобы настроить подписку, запустите "+watcherPath+" setup")
				return nil
			}
			parsed, err := url.Parse(address)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
				return fmt.Errorf("нужна ссылка подписки, начинающаяся с https:// или http://")
			}
			mode, err := readSetupMode(in, out)
			if err != nil {
				return err
			}
			return p.update(address, mode, out)
		},
	}
}

func (p managedPaths) newRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Обновить настроенную подписку",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.update("", "", cmd.OutOrStdout())
		},
	}
}

func readSetupLine(in *bufio.Reader) (string, error) {
	text, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("не удалось прочитать ввод: %w", err)
	}
	return strings.TrimSpace(text), nil
}

func readSetupMode(in *bufio.Reader, out io.Writer) (string, error) {
	for {
		fmt.Fprintln(out, "1. Заменить балансировщики и мониторинг Xray, сохранив правила маршрутизации.")
		fmt.Fprintln(out, "2. Только создать файл с серверами подписки.")
		fmt.Fprint(out, "Выберите 1 или 2 [2]: ")
		answer, err := readSetupLine(in)
		if err != nil {
			return "", err
		}
		switch answer {
		case "1":
			return modeBalance, nil
		case "", "2":
			return modeOutbounds, nil
		default:
			fmt.Fprintln(out, "Введите 1 или 2.")
		}
	}
}

func compileManagedSubscription(body string) (managedProfile, error) {
	if strings.HasPrefix(body, "[") || strings.HasPrefix(body, "{") {
		entries, err := parseXraySubscription(body)
		if err != nil {
			return managedProfile{}, err
		}
		return ordinaryManagedProfile(entries)
	}
	return ordinaryManagedProfile(parseLinkOutbounds(body, managedTag, false))
}

func (p managedPaths) update(address, mode string, out io.Writer) error {
	if err := os.MkdirAll(p.stateDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(p.stateDir, "update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}

	settingPath := filepath.Join(p.stateDir, managedStateName)
	previous, err := readRouterFile(settingPath)
	if err != nil {
		return err
	}
	var settings managedSubscription
	if previous.exists {
		if err := json.Unmarshal(previous.data, &settings); err != nil || !subscriptionTag.MatchString(settings.Tag) {
			return fmt.Errorf("не удалось прочитать сохранённые настройки подписки")
		}
	}
	isSetup := address != ""
	if isSetup {
		settings.URL = address
		settings.Mode = mode
	} else if settings.URL == "" {
		return fmt.Errorf("сначала запустите %s setup", watcherPath)
	}
	if settings.Mode != modeBalance && settings.Mode != modeOutbounds {
		return fmt.Errorf("не выбран режим обновления, запустите %s setup", watcherPath)
	}
	if isSetup {
		if err := routerCommand("crontab").Err; err != nil {
			return fmt.Errorf("нет crontab; установите пакет cron в Entware")
		}
	}
	if settings.Mode == modeBalance {
		for _, name := range []string{"xray", "xkeen"} {
			if err := routerCommand(name).Err; err != nil {
				return fmt.Errorf("нет %s; установите XKeen с ядром Xray или выберите режим «Только серверы»", name)
			}
		}
	}
	body, err := fetchSubscription(subscription{tag: managedTag, url: settings.URL}, p.detectHWID)
	if err != nil {
		return fmt.Errorf("не удалось получить подписку: %w", err)
	}
	profile, err := compileManagedSubscription(body)
	if err != nil {
		return err
	}
	var oldCron, newCron []byte
	if isSetup {
		oldCron, err = loadCrontab()
		if err != nil {
			return err
		}
		newCron, settings.Tag, err = prepareManagedCron(oldCron, settings.URL, settings.Tag)
		if err != nil {
			return err
		}
	}
	previousTag := settings.Tag
	if previousTag == "resist" {
		settings.Tag = managedTag
	}
	renaming := previousTag != settings.Tag
	files, err := p.prepareXrayChanges(profile, previousTag, settings.Tag, settings.Mode == modeBalance)
	if err != nil {
		return err
	}
	configChanged := len(files) != 0
	if isSetup || renaming {
		data, err := encodeXrayObject(settings)
		if err != nil {
			return err
		}
		files = append(files, routerChange{before: previous, data: data, mode: 0600})
		backup, err := p.backupXrayConfig()
		if err != nil {
			return fmt.Errorf("не удалось скопировать конфиги Xray: %w", err)
		}
		fmt.Fprintf(out, "Копия конфигов Xray: %s\n", backup)
	}
	if isSetup {
		backup, err := p.backupSetup(previous, oldCron)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Копия настроек Watcher и crontab: %s\n", backup)
	}
	restart := configChanged && settings.Mode == modeBalance
	if err := applyRouterChanges(files, oldCron, newCron, restart); err != nil {
		return err
	}
	if isSetup {
		fmt.Fprintln(out, "Подписка настроена. Загружены отдельные серверы.")
		if settings.Mode == modeBalance {
			fmt.Fprintln(out, "Для VPN-маршрутов используйте balancerTag proxy в правилах Xray.")
		} else {
			fmt.Fprintln(out, "Файл серверов готов. Примените его вручную через XKeen.")
		}
		fmt.Fprintln(out, "Чтобы поменять ссылку или режим, запустите "+watcherPath+" setup")
	} else if configChanged {
		fmt.Fprintln(out, "Подписка обновлена.")
	}
	if restart {
		fmt.Fprintln(out, "XKeen перезапущен.")
	}
	return nil
}

type routerFile struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

type routerChange struct {
	before routerFile
	data   []byte
	mode   os.FileMode
	remove bool
}

func (change routerChange) apply(path string) error {
	if change.remove {
		return os.Remove(path)
	}
	return replaceFile(path, change.data, change.mode)
}

func readRouterFile(path string) (routerFile, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return routerFile{path: path}, nil
	}
	if err != nil {
		return routerFile{}, err
	}
	if !info.Mode().IsRegular() {
		return routerFile{}, fmt.Errorf("%s должен быть обычным файлом", path)
	}
	data, err := os.ReadFile(path)
	return routerFile{path: path, data: data, mode: info.Mode().Perm(), exists: true}, err
}

func loadCrontab() ([]byte, error) {
	cmd := routerCommand("crontab", "-l")
	data, err := cmd.Output()
	if err == nil {
		return data, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		message := strings.ToLower(strings.TrimSpace(string(exit.Stderr)))
		if message == "" || strings.Contains(message, "no crontab") || strings.Contains(message, "no such file or directory") {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("не удалось прочитать crontab: %w", err)
}

func writeCrontab(data []byte) error {
	cmd := routerCommand("crontab", "-")
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось обновить crontab: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p managedPaths) backupSetup(settings routerFile, cron []byte) (string, error) {
	root := filepath.Join(p.stateDir, "backups")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "setup.")
	if err != nil {
		return "", err
	}
	if settings.exists {
		if err := os.WriteFile(filepath.Join(dir, managedStateName), settings.data, 0600); err != nil {
			return "", err
		}
	}
	return dir, os.WriteFile(filepath.Join(dir, "crontab"), cron, 0600)
}

func applyRouterChanges(files []routerChange, oldCron, newCron []byte, restart bool) error {
	rollback := func(cause error, applied []routerChange, restoreCron, restartOld bool) error {
		if restoreCron {
			cause = errors.Join(cause, writeCrontab(oldCron))
		}
		for i := len(applied) - 1; i >= 0; i-- {
			old := applied[i].before
			if old.exists {
				cause = errors.Join(cause, replaceFile(old.path, old.data, old.mode))
			} else {
				cause = errors.Join(cause, os.Remove(old.path))
			}
		}
		if restartOld {
			cause = errors.Join(cause, restartManagedXKeen())
		}
		return cause
	}
	for index, file := range files {
		if err := file.apply(file.before.path); err != nil {
			return rollback(err, files[:index], false, false)
		}
	}
	cronChanged := newCron != nil && !bytes.Equal(oldCron, newCron)
	if cronChanged {
		if err := writeCrontab(newCron); err != nil {
			return rollback(err, files, true, false)
		}
	}
	if restart {
		if err := restartManagedXKeen(); err != nil {
			return rollback(err, files, cronChanged, true)
		}
	}
	return nil
}

func restartManagedXKeen() error {
	if output, err := routerCommand("xkeen", "-restart").CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось перезапустить XKeen: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func routerCommand(name string, args ...string) *exec.Cmd {
	if path, err := exec.LookPath(name); err == nil {
		return exec.Command(path, args...)
	}
	for _, directory := range []string{"/opt/sbin", "/opt/bin"} {
		if path, err := exec.LookPath(filepath.Join(directory, name)); err == nil {
			return exec.Command(path, args...)
		}
	}
	return exec.Command(name, args...)
}
