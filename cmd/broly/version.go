package main

import (
	"fmt"
	"runtime/debug"
	"strings"
)

type versionInfo struct {
	Version       string
	Commit        string
	ModuleVersion string
	VCSRevision   string
	VCSTime       string
	ModifiedKnown bool
	Modified      bool
}

func currentVersionInfo() versionInfo {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		buildInfo = nil
	}
	return resolveVersionInfo(version, commit, buildInfo)
}

func resolveVersionInfo(ldVersion, ldCommit string, info *debug.BuildInfo) versionInfo {
	result := versionInfo{
		Version: fallbackValue(ldVersion, "dev"),
		Commit:  fallbackValue(ldCommit, "none"),
	}

	if info == nil {
		return result
	}

	if info.Main.Version != "" {
		result.ModuleVersion = info.Main.Version
		if (ldVersion == "" || ldVersion == "dev") && info.Main.Version != "(devel)" {
			result.Version = info.Main.Version
		}
	}

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			result.VCSRevision = shortenCommit(setting.Value)
			if ldCommit == "" || ldCommit == "none" {
				result.Commit = shortenCommit(setting.Value)
			}
		case "vcs.time":
			result.VCSTime = setting.Value
		case "vcs.modified":
			result.ModifiedKnown = true
			result.Modified = setting.Value == "true"
		}
	}

	return result
}

func formatVersionInfo(info versionInfo) string {
	var lines []string
	lines = append(lines, "broly")
	lines = append(lines, fmt.Sprintf("  version:  %s", fallbackValue(info.Version, "dev")))
	lines = append(lines, fmt.Sprintf("  commit:   %s", fallbackValue(info.Commit, "none")))
	if info.ModuleVersion != "" {
		lines = append(lines, fmt.Sprintf("  module:   %s", info.ModuleVersion))
	}
	if info.VCSRevision != "" {
		lines = append(lines, fmt.Sprintf("  vcs rev:  %s", info.VCSRevision))
	}
	if info.VCSTime != "" {
		lines = append(lines, fmt.Sprintf("  vcs time: %s", info.VCSTime))
	}
	if info.ModifiedKnown {
		lines = append(lines, fmt.Sprintf("  modified: %t", info.Modified))
	}
	return strings.Join(lines, "\n")
}

func fallbackValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func shortenCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
