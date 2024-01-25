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

	"github.com/spf13/cobra"
	"github.com/threatkey-oss/hvresult/internal/gitops"
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Emits markdown of changes to the RSoP of a git repository",
	Long: `Emits a markdown tables for changes to the RSoP of each auth principal
modified in a git repository.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			ctx           = context.Background()
			_f            = cmd.Flags()
			directory, _  = _f.GetString("directory")
			compareRef, _ = _f.GetString("compare-ref")
		)
		gitops.MustEmitMarkdownDiffs(ctx, directory, compareRef)
	},
}

func init() {
	gitopsCmd.AddCommand(diffCmd)
	flags := diffCmd.Flags()
	flags.String("compare-ref", "", "if specified, compare to this git reference instead of the default branch (e.g. 'main')")
}
