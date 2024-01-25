package gitops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/rs/zerolog/log"
	"github.com/threatkey-oss/hvresult/internal"
)

// Prints RSoPDifferential tables for all changes made to auth principals and policies between `compareRef` and the current working copy.
//
// Uses log.Fatal() instead of returning an error because it's directly called by a command.
func MustEmitMarkdownDiffs(ctx context.Context, gitDirectory, compareRef string) {
	changes, compareRef, err := GetChangedFiles(ctx, gitDirectory, compareRef)
	if err != nil {
		log.Fatal().Err(err).Msg("error getting changed files")
	}
	log.Info().Int("count", len(changes)).Msg("detected changes to files")
	policyDirectory := filepath.Join(gitDirectory, "sys", "policies", "acl")
	if _, err := os.Stat(policyDirectory); err != nil {
		logger := log.With().Str("path", policyDirectory).Logger()
		if errors.Is(err, os.ErrNotExist) {
			logger.Fatal().Msg("policy directory nonexistent - wrong directory specified?")
		}
		logger.Fatal().Err(err).Msg("error checking policy directory")
	}
	var (
		relativePolicyDirectory = filepath.Join("sys", "policies", "acl")
		changedPaths            = []string{}
		diffs                   = map[string]*internal.RSoPDifferential{}
	)
	for _, change := range changes {
		if _, exists := diffs[change.Path]; exists {
			continue
		}
		logger := log.With().Str("path", change.Path).Logger()
		if change.Principal {
			logger.Info().Msg("processing principal change")
			diff, err := GetAuthPrincipalDifferential(gitDirectory, change.Path, relativePolicyDirectory, compareRef)
			if err != nil {
				log.Err(err).Msg("error getting differential for auth principal")
			}
			logger.Debug().Any("diff", diff).Msg("computed differential")
			changedPaths = append(changedPaths, change.Path)
			diffs[change.Path] = diff
		} else if change.Policy {
			logger.Info().Msg("processing policy change")
			affected, err := GetPolicyChangeDifferentials(changes, gitDirectory, filepath.Base(change.Path), relativePolicyDirectory, "auth", compareRef)
			if err != nil {
				logger.Fatal().Err(err).Msg("error getting differentials for policy change")
			}
			// keeps the output deterministic
			keys := make([]string, 0, len(affected))
			for path := range affected {
				// skip already computed
				// TODO: easy optimization for the thoughtful
				if _, exists := diffs[path]; exists {
					continue
				}
				keys = append(keys, path)
			}
			sort.StringSlice(keys).Sort()
			for _, path := range keys {
				changedPaths = append(changedPaths, path)
				diffs[path] = affected[path]
			}
		}
	}
	for _, path := range changedPaths {
		diff := diffs[path]
		if diff.Empty() {
			fmt.Printf("0 effective changes to `%s` (policy assignment change is a no-op).\n\n", path)
		} else {
			metrics := diff.Metrics()
			var changeWord string
			if metrics.CapabilityChanges == 1 {
				changeWord = "change"
			} else {
				changeWord = "changes"
			}
			fmt.Printf("%d effective %s to `%s`.\n\n", metrics.CapabilityChanges, changeWord, path)
			fmt.Println(diff.MarkdownTable())
		}
	}
}
