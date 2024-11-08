//go:build js && wasm
// +build js,wasm

package main

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "dev"
	CommitSHA = "unknown"
	BuildTime = "unknown"
)

func init() {
	if info, available := debug.ReadBuildInfo(); available {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				CommitSHA = setting.Value
			case "vcs.time":
				BuildTime = setting.Value
			}
		}
	}
}

// PrintBuildInfo prints the build information
func PrintBuildInfo() {
	fmt.Printf("ARK SDK WebAssembly Module\n")
	fmt.Printf("Version: %s\n", Version)
	fmt.Printf("Commit: %s\n", CommitSHA)
	fmt.Printf("Build Time: %s\n", BuildTime)
}

// GetVersion returns the version string
func GetVersion() string {
	return Version
}
