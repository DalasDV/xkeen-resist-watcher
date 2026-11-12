package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const watcherPath = "/opt/sbin/xkeen-subscription-watcher"

var subscriptionTag = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

type watcherJob struct {
	index    int
	schedule string
	tag      string
	url      string
	refresh  bool
}

func readWatcherJobs(lines []string) []watcherJob {
	var jobs []watcherJob
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		scheduleFields := 5
		if strings.HasPrefix(fields[0], "@") {
			scheduleFields = 1
		}
		if len(fields) <= scheduleFields || filepath.Base(fields[scheduleFields]) != filepath.Base(watcherPath) {
			continue
		}
		job := watcherJob{index: index, schedule: strings.Join(fields[:scheduleFields], " ")}
		args := fields[scheduleFields+1:]
		if len(args) == 1 && args[0] == "refresh" {
			job.refresh = true
			jobs = append(jobs, job)
			continue
		}
		var positional []string
		for _, arg := range args {
			switch arg {
			case "--no-restart", "--protocol-tags", "--single-proxy":
			default:
				positional = append(positional, strings.Trim(arg, "'\""))
			}
		}
		if len(positional) != 1 {
			continue
		}
		tag, url, ok := strings.Cut(positional[0], "=")
		if ok && subscriptionTag.MatchString(tag) && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
			job.tag, job.url = tag, url
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func prepareManagedCron(content []byte, url, previousTag string) ([]byte, string, error) {
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	jobs := readWatcherJobs(lines)
	var matches []watcherJob
	var old []watcherJob
	for _, job := range jobs {
		if job.refresh {
			matches = append(matches, job)
		} else if job.url == url || previousTag != "" && job.tag == previousTag {
			matches = append(matches, job)
		} else {
			old = append(old, job)
		}
	}
	if len(matches) == 0 && previousTag == "" && len(old) == 1 {
		matches = old
	}

	tag := previousTag
	schedule := "0 * * * *"
	replaced := make(map[int]bool)
	for _, job := range matches {
		if len(replaced) == 0 {
			schedule = job.schedule
		}
		if job.tag != "" {
			if tag != "" && tag != job.tag {
				return nil, "", fmt.Errorf("несколько записей watcher используют эту подписку под разными тегами")
			}
			tag = job.tag
		}
		replaced[job.index] = true
	}
	if tag == "" {
		tag = managedTag
	}
	var updated []string
	inserted := false
	for i, line := range lines {
		if replaced[i] {
			if !inserted {
				updated = append(updated, schedule+" "+watcherPath+" refresh")
				inserted = true
			}
		} else if len(lines) > 1 || line != "" {
			updated = append(updated, line)
		}
	}
	if !inserted {
		updated = append(updated, schedule+" "+watcherPath+" refresh")
	}
	return []byte(strings.Join(updated, "\n") + "\n"), tag, nil
}
