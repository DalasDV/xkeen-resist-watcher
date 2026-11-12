package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func (p managedPaths) backupXrayConfig() (string, error) {
	root := filepath.Join(p.configDir, "watcher-backup")
	if err := os.Mkdir(root, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s должен быть обычным каталогом", root)
	}
	snapshot, err := os.MkdirTemp(root, "setup.")
	if err != nil {
		return "", err
	}
	err = filepath.WalkDir(p.configDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		switch path {
		case root:
			return filepath.SkipDir
		case p.configDir:
			return nil
		}
		rel, err := filepath.Rel(p.configDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(snapshot, rel)
		switch {
		case entry.IsDir():
			return os.Mkdir(target, 0700)
		case entry.Type()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case entry.Type().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0600)
		}
		return nil
	})
	if err != nil {
		os.RemoveAll(snapshot)
		return "", err
	}
	return snapshot, nil
}
