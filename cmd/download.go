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
	"path/filepath"

	vault "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/threatkey-oss/hvresult/internal/gitops"
)

// downloadCmd represents the download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download Vault policy and auth roles to a local directory",
	Long: `Can be used to initialize a GitOps repository that reflects the 
current state of Vault auth roles and policies required in order to 
start using pull requests for Vault policy change management.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			ctx          = context.Background()
			_f           = cmd.Flags()
			directory, _ = _f.GetString("directory")
		)
		vc, err := vault.NewClient(vault.DefaultConfig())
		if err != nil {
			log.Fatal().Err(err).Msg("error creating Vault client from defaults")
		}
		// do the thing that's more error prone first
		if err := gitops.DownloadAuth(ctx, vc, filepath.Join(directory, "auth")); err != nil {
			log.Fatal().Err(err).Msg("error downloading auth mounts")
		}
		if err := gitops.DownloadPolicies(ctx, vc, filepath.Join(directory, "sys", "policies", "acl")); err != nil {
			log.Fatal().Err(err).Msg("error downloading policies")
		}
	},
}

func init() {
	gitopsCmd.AddCommand(downloadCmd)
}
