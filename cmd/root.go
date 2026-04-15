package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the release version (overridden at link time in CI for tagged builds).
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "cf-knife",
	Version: Version,
	Short:   "The ultimate Swiss-Army-knife Cloudflare IP scanner",
	Long: `cf-knife combines the speed of masscan/zmap with the rich probing
of nmap — all in a single cross-platform binary purpose-built for
Cloudflare IP scanning.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
