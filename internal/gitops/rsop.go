package gitops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/threatkey-oss/hvresult/internal"
)

// GetAuthPrincipalDifferential compares policies for an auth principal in the working copy to a historical git ref.
func GetAuthPrincipalDifferential(repositoryPath, relativePrincipalPath, relativePolicyDirectory, historicalGitRef string) (*internal.RSoPDifferential, error) {
	git := Git{Dir: repositoryPath}
	currentPolicies, err := readPrincipalPolicies(git, relativePrincipalPath, relativePolicyDirectory, "")
	if err != nil {
		return nil, fmt.Errorf("error getting policies for working copy: %w", err)
	}
	historicalPolicies, err := readPrincipalPolicies(git, relativePrincipalPath, relativePolicyDirectory, historicalGitRef)
	if err != nil {
		return nil, fmt.Errorf("error getting policies for historical copy: %w", err)
	}
	var (
		historical = internal.RSoP{Policies: historicalPolicies}
		current    = internal.RSoP{Policies: currentPolicies}
		hcapmap    = historical.GetCapabilityMap()
		ccapmap    = current.GetCapabilityMap()
		diff       = hcapmap.Diff(ccapmap)
	)
	log.Debug().Any("historical", hcapmap).Any("current", ccapmap).Send()
	return diff, nil
}

// GetPolicyChangeDifferentials returns an RSoP differential for every auth principal that involves this policy.
func GetPolicyChangeDifferentials(
	changedFiles []ChangedFile,
	repositoryPath, policyName,
	relativePolicyDirectory, relativePrincipalDirectory,
	historicalGitRef string,
) (map[string]*internal.RSoPDifferential, error) {
	// TODO: make some sort of cache thing for Windows and IOPS-constrainted runtimes
	var (
		git                = Git{Dir: repositoryPath}
		affectedPrincipals = make(map[string]*internal.RSoPDifferential, len(changedFiles))
	)
	// determine if any relevant files got deleted
	// (these are not covered by the filepath.WalkDir invocation below)
	for _, changed := range changedFiles {
		if changed.Principal && changed.Mutation == Delete {
			policies, err := readPrincipalPolicies(git, changed.Path, relativePolicyDirectory, historicalGitRef)
			if err != nil {
				return nil, fmt.Errorf("error reading policies for deleted auth principal %s: %w", changed.Path, err)
			}
			var relevant bool
			for _, policy := range policies {
				if policy.Name == policyName {
					relevant = true
					break
				}
			}
			if relevant {
				rsop := &internal.RSoP{Policies: policies}
				diff := rsop.GetCapabilityMap().Diff(internal.RSoPCapMap{})
				affectedPrincipals[changed.Path] = diff
			}
		}
	}
	// crawl everything else
	absWalkRoot, err := filepath.Abs(filepath.Join(repositoryPath, relativePrincipalDirectory))
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path of auth principal directory: %w", err)
	}
	log.Debug().Str("root", absWalkRoot).Str("policy", policyName).Msg("walking auth directory for policy matches")
	err = filepath.WalkDir(absWalkRoot, func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var authData authPrincipalData
		if err := json.Unmarshal(content, &authData); err != nil {
			return fmt.Errorf("error unmarshalling %s as auth principal data: %w", path, err)
		}
		for _, name := range authData.AllPolicies() {
			if name == policyName {
				relPath, err := filepath.Rel(git.Dir, path)
				if err != nil {
					return fmt.Errorf("error getting relative path to auth principal: %w", err)
				}
				diff, err := GetAuthPrincipalDifferential(git.Dir, relPath, relativePolicyDirectory, historicalGitRef)
				if err != nil {
					return err
				}
				affectedPrincipals[relPath] = diff
				return nil
			}
		}
		return nil
	})
	return affectedPrincipals, err
}

// when gitRef is the empty string, this reads from the working copy.
func readPrincipalPolicies(git Git, relativePrincipalPath, relativePolicyDirectory, historicalGitRef string) ([]*internal.Policy, error) {
	var (
		principalData []byte
		readThing     string
	)
	if historicalGitRef == "" {
		// working copy
		readThing = filepath.Join(git.Dir, relativePrincipalPath)
		data, err := os.ReadFile(readThing)
		if err != nil {
			return nil, fmt.Errorf("error reading working copy auth principle file at '%s': %w", readThing, err)
		}
		principalData = data
	} else {
		readThing = fmt.Sprintf("%s:%s", historicalGitRef, relativePrincipalPath)
		contentStr, err := git.CombinedOutput("show", readThing)
		if err != nil {
			return nil, fmt.Errorf("error getting auth principal file at ref %s: %w", readThing, err)
		}
		log.Debug().Str("output", contentStr).Msgf("git show %s", readThing)
		principalData = []byte(contentStr)
	}
	// find out what policies apply
	var data authPrincipalData
	if err := json.Unmarshal(principalData, &data); err != nil {
		return nil, fmt.Errorf("error unmarshalling %s as auth principal data: %w", readThing, err)
	}
	// get policies
	var (
		allPolicies = data.AllPolicies()
		policies    = make([]*internal.Policy, 0, len(allPolicies))
	)
	for _, policyName := range allPolicies {
		var (
			policyReadThing string
			policyData      string
			err             error
		)
		if historicalGitRef == "" {
			policyReadThing = filepath.Join(git.Dir, relativePolicyDirectory, policyName)
			data, err := os.ReadFile(policyReadThing)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					log.Warn().Err(err).Msg("referenced policy does not exist on disk, treating as empty")
					continue
				}
				return nil, fmt.Errorf("error reading working copy policy file at '%s': %w", readThing, err)
			}
			policyData = string(data)
		} else {
			policyReadThing = fmt.Sprintf("%s:%s", historicalGitRef, filepath.Join(relativePolicyDirectory, policyName))
			policyData, err = git.CombinedOutput("show", policyReadThing)
			if err != nil {
				return nil, fmt.Errorf("error getting policy file at ref %s: %w", policyReadThing, err)
			}
		}
		policy, err := internal.ParsePolicy(policyData, policyName)
		if err != nil {
			return nil, fmt.Errorf("error parsing %s: %w", policyData, err)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}
