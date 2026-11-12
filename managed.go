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
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const managedStateName = "subscription.json"

type managedSubscription struct {
	URL     string `json:"url"`
	Profile string `json:"profile,omitempty"`
	Tag     string `json:"tag"`
}

type managedPaths struct {
	configDir string
	stateDir  string
}

var routerPaths = managedPaths{
	configDir: "/opt/etc/xray/configs",
	stateDir:  "/opt/etc/xkeen-subscription-watcher",
}

func newSetupCmd() *cobra.Command {
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
			return routerPaths.update(address, in, out)
		},
	}
}

func newRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Обновить настроенную подписку",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return routerPaths.update("", nil, cmd.OutOrStdout())
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

func selectManagedProfile(body, saved string, in *bufio.Reader, out io.Writer) (managedProfile, string, error) {
	if strings.HasPrefix(body, "[") || strings.HasPrefix(body, "{") {
		profiles, err := decodeXrayProfiles(body)
		if err != nil {
			return managedProfile{}, "", err
		}
		candidates := findManagedProfiles(profiles)
		if in == nil && saved != "" {
			matches := slices.DeleteFunc(candidates, func(p managedProfile) bool { return p.name != saved })
			if len(matches) != 1 {
				return managedProfile{}, "", fmt.Errorf("сохранённый профиль автобалансировки исчез или неоднозначен. Запустите setup")
			}
			return matches[0], saved, nil
		}
		if len(candidates) == 1 {
			return candidates[0], candidates[0].name, nil
		}
		if len(candidates) > 1 && in == nil {
			return managedProfile{}, "", fmt.Errorf("в подписке несколько профилей автобалансировки. Запустите setup")
		}
		if len(candidates) > 1 && in != nil {
			fmt.Fprintln(out, "Выберите профиль автобалансировки:")
			for i, p := range candidates {
				fmt.Fprintf(out, "%d. %s\n", i+1, p.name)
			}
			fmt.Fprint(out, "Номер профиля: ")
			answer, err := readSetupLine(in)
			if err != nil {
				return managedProfile{}, "", err
			}
			index, err := strconv.Atoi(answer)
			if err != nil || index < 1 || index > len(candidates) {
				return managedProfile{}, "", fmt.Errorf("неверный номер профиля")
			}
			profile := candidates[index-1]
			for i, candidate := range candidates {
				if i != index-1 && candidate.name == profile.name {
					return managedProfile{}, "", fmt.Errorf("у нескольких профилей одинаковое имя. Укажите уникальные названия в панели")
				}
			}
			return profile, profile.name, nil
		}
		entries, err := parseXraySubscription(body)
		if err != nil {
			return managedProfile{}, "", err
		}
		profile, err := ordinaryManagedProfile(entries)
		return profile, "", err
	}
	if in == nil && saved != "" {
		return managedProfile{}, "", fmt.Errorf("профиль автобалансировки требует выдачу Xray JSON")
	}
	profile, err := ordinaryManagedProfile(parseLinkOutbounds(body, managedTag, false))
	return profile, "", err
}

func (p managedPaths) update(address string, in *bufio.Reader, out io.Writer) error {
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
	isSetup := in != nil
	if isSetup {
		settings.URL = address
	} else if settings.URL == "" {
		return fmt.Errorf("сначала запустите %s setup", watcherPath)
	}
	body, err := fetchSubscription(subscription{tag: managedTag, url: settings.URL})
	if err != nil {
		return fmt.Errorf("не удалось получить подписку: %w", err)
	}
	profile, profileName, err := selectManagedProfile(body, settings.Profile, in, out)
	if err != nil {
		return err
	}
	settings.Profile = profileName
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
	files, err := p.prepareXrayChanges(profile, settings.Tag)
	if err != nil {
		return err
	}
	configChanged := len(files) != 0
	if isSetup {
		data, err := encodeXrayObject(settings)
		if err != nil {
			return err
		}
		files = append(files, routerChange{before: previous, data: data, mode: 0600})
		backup, err := p.backupSetup(files, oldCron)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Резервная копия: %s\n", backup)
	}
	if err := applyRouterChanges(files, oldCron, newCron, configChanged); err != nil {
		return err
	}
	if isSetup {
		fmt.Fprintf(out, "Подписка настроена. Профиль: %s.\n", profile.name)
		fmt.Fprintln(out, "Чтобы поменять ссылку, запустите "+watcherPath+" setup")
	} else if configChanged {
		fmt.Fprintln(out, "Подписка обновлена.")
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

func (p managedPaths) backupSetup(files []routerChange, cron []byte) (string, error) {
	root := filepath.Join(p.stateDir, "backups")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "setup.")
	if err != nil {
		return "", err
	}
	for _, change := range files {
		if change.before.exists {
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(change.before.path)), change.before.data, 0600); err != nil {
				return "", err
			}
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
		if err := replaceFile(file.before.path, file.data, file.mode); err != nil {
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
