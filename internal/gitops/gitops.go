// Package gitops handles interpreting changes to a git repository as RSoP differentials.
package gitops

import (
	"bufio"
	"bytes"
	"context"
	"encoding"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

//go:generate stringer -type Mutation
type Mutation int

// MarshalText implements encoding.TextMarshaler.
func (m Mutation) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

const (
	Add Mutation = iota
	Delete
	Change
)

type ChangedFile struct {
	Path      string
	Mutation  Mutation
	Principal bool `json:",omitempty"`
	Policy    bool `json:",omitempty"`
}

// Computes a change between HEAD and some reference, like a branch. Leave blank to use the default branch, which is usually named main or master.
//
// Returns the branch used.
func GetChangedFiles(ctx context.Context, repo string, referenceName string) ([]ChangedFile, string, error) {
	git := Git{Dir: repo}
	if referenceName == "" {
		output, err := git.CombinedOutput("config", "init.defaultBranch")
		if err != nil {
			var exitErr *exec.ExitError
			// ignore not found
			if !(errors.As(err, &exitErr) && exitErr.ExitCode() == 1) {
				return nil, referenceName, fmt.Errorf("error running `git config init.defaultBranch`:%w: %s", err, output)
			}
		}
		referenceName = output
		if referenceName == "" {
			referenceName, err = guessDefaultBranch(git)
			if err != nil {
				return nil, referenceName, fmt.Errorf("error guessing default branch: %w", err)
			}
			log.Info().Str("branch", referenceName).Msg("`git config init.defaultBranch` returned nothing, guessed default branch")
		}
	}
	output, err := git.CombinedOutput("diff", referenceName, "--name-status")
	if err != nil {
		return nil, referenceName, fmt.Errorf("error running `git diff %s --name-status`: %w: %s", referenceName, err, output)
	}
	log.Debug().Str("output", output).Msgf("git diff %s --name-status", referenceName)
	var (
		changes []ChangedFile
		reader  = bufio.NewReader(strings.NewReader(output))
		done    bool
	)
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			done = true
		} else if err != nil {
			return nil, referenceName, fmt.Errorf("error parsing git diff: %w", err)
		}
		splitLine := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(splitLine) != 2 {
			log.Debug().Strs("line", splitLine).Msg("ignoring unexpected line split")
			continue
		}
		var (
			mutation Mutation
			path     = splitLine[1]
		)
		// Added (A), Copied (C), Deleted (D), Modified (M), Renamed (R), have their type (i.e. regular file, symlink,
		// submodule, ...) changed (T), are Unmerged (U), are Unknown (X), or have had their pairing Broken (B)
		// - man git-diff
		switch status := splitLine[0]; status {
		case "A", "C":
			mutation = Add
		case "D":
			mutation = Delete
		case "M":
			mutation = Change
		default:
			log.Warn().Str("status", status).Msg("unhandled git file status, skipping")
			continue
		}
		cf := ChangedFile{
			Path:     path,
			Mutation: mutation,
		}
		// this heuristic might need adjustment
		if strings.HasPrefix(path, "auth") {
			cf.Principal = true
		} else if strings.HasSuffix(filepath.Dir(path), "acl") {
			cf.Policy = true
		}
		changes = append(changes, cf)
		if done {
			break
		}
	}
	return changes, referenceName, nil
}

// A little wrapper for subprocess commands to git.
//
// If you're curious about why, github.com/go-git/go-git can get a little dicey and bugs are more easily triaged this way.
type Git struct {
	Dir string
}

func (g Git) CombinedOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Dir
	combined, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("error running git %s: %w", strings.Join(args, " "), err)
	}
	return string(bytes.TrimSpace(combined)), err
}

// uses the heuristic of "the last line of the git branch command"
func guessDefaultBranch(g Git) (string, error) {
	output, err := g.CombinedOutput("branch")
	if err != nil {
		return "", fmt.Errorf("error running git branch: %w: %s", err, output)
	}
	if output == "" {
		return "", errors.New("git branch output empty")
	}
	lines := strings.Split(output, "\n")
	return strings.TrimSpace(
		strings.TrimLeft(lines[len(lines)-1], "*"),
	), nil
}

var (
	_ encoding.TextMarshaler = Add
)
