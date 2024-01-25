/*
Copyright © 2024 ThreatKey, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/threatkey-oss/hvresult/internal"
	"golang.org/x/term"
)

var (
	cfgFile     string
	flagVerbose bool
	flagFormat  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hvresult",
	Short: "Analyzes Vault identities and their policies",
	Long: `Each argument will be evaluated as either a Vault token, token accessor,
path to a Vault role, or server path to a Vault entity/group/etc.

By default, hvresult will evaluate and print the RSoP for each.
`,
	Args: cobra.MinimumNArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if flagVerbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		// pretty colors to stderr for humans
		if term.IsTerminal(int(os.Stdin.Fd())) {
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		}
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		flagFormat = strings.ToLower(flagFormat)
		switch flagFormat {
		case "hcl", "table":
			// cool
		default:
			log.Fatal().Msg("--format must be one")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		vc, err := vault.NewClient(vault.DefaultConfig())
		if err != nil {
			log.Fatal().Err(err).Msg("error creating Vault client from defaults")
		}
		if vc.Token() == "" {
			log.Fatal().Msg("Vault client from defaults has no token - VAULT_TOKEN environment variable is probably empty")
		}
		pp, err := internal.NewReadthroughPolicyProvider("", vc)
		if err != nil {
			log.Fatal().Err(err).Msg("error creating PolicyProvider")
		}
		for _, arg := range args {
			rsop, err := pp.GetRSoP(ctx, arg)
			if err != nil {
				log.Fatal().Err(err).Msg("error generating RSoP")
			}
			log.Debug().EmbedObject(rsop).Msgf("printing as %s to stdout", flagFormat)
			capmap := rsop.GetCapabilityMap()
			switch flagFormat {
			case "hcl":
				fmt.Println(strings.TrimSpace(capmap.HCL()))
			case "table":
				empty := &internal.RSoPCapMap{}
				diff := empty.Diff(capmap)
				log.Debug().Any("diff", diff).Msg("generated diff")
				fmt.Println(diff.MarkdownTable())
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	persistent := rootCmd.PersistentFlags()
	persistent.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hvaa.yaml)")
	persistent.BoolVarP(&flagVerbose, "verbose", "v", false, "print debug level logs")
	flags := rootCmd.Flags()
	flags.StringVar(&flagFormat, "format", "hcl", "output format")
	flags.BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".hvap" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".hvap")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
