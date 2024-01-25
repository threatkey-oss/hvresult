package gitops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type authListData struct {
	Keys []string `mapstructure:"keys"`
}

type authPrincipalData struct {
	Policies        []string `mapstructure:"policies,omitempty" json:"policies,omitempty"`
	TokenPolicies   []string `mapstructure:"token_policies,omitempty" json:"token_policies,omitempty"`
	AllowedPolicies []string `mapstructure:"allowed_policies,omitempty" json:"allowed_policies,omitempty"`
}

// Merges and sorts TokenPolicies, AllowedPolicies, and Policies.
func (a authPrincipalData) AllPolicies() []string {
	all := append(
		append(
			a.TokenPolicies,
			a.AllowedPolicies...,
		),
		a.Policies...,
	)
	sort.StringSlice(all).Sort()
	return all
}

func DownloadAuth(ctx context.Context, vc *vault.Client, authDirectory string) error {
	mounts, err := vc.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error listing auth mounts: %w", err)
	}
	vaultLogical := vc.Logical()
	for name, mount := range mounts {
		log.Debug().Str("name", name).Any("mount", mount).Send()
		abspath := strings.TrimRight(fmt.Sprintf("auth/%s", name), "/")
		// map of auth/mount/endpointToList -> auth/mount/endpointToGet/{roleName}
		var rolePaths map[string]string
		switch mount.Type {
		// all "official" mounts first
		case "aws", "gcp":
			rolePaths = map[string]string{
				abspath + "/roles": abspath + "/role/",
			}
		case "azure", "kubernetes", "oidc", "oci", "saml":
			rolePaths = map[string]string{
				abspath + "/role": abspath + "/role/",
			}
		case "kerberos":
			rolePaths = map[string]string{
				abspath + "/groups": abspath + "/groups/",
			}
		case "ldap", "okta":
			rolePaths = map[string]string{
				abspath + "/groups": abspath + "/groups/",
				abspath + "/users":  abspath + "/users/",
			}
		case "radius":
			rolePaths = map[string]string{
				abspath + "/users": abspath + "/users/",
			}
		case "token":
			rolePaths = map[string]string{
				abspath + "/roles": abspath + "/roles/",
			}
		// TODO: support cert mount
		default:
			return fmt.Errorf("unknown paths for listing Vault identities for this mount type: '%s'", mount.Type)
		}
		var mountPrincipalCount int
		for listPath, readPathPrefix := range rolePaths {
			var targetDir string
			if filepath.Separator == '/' {
				targetDir = filepath.Join(authDirectory, name, filepath.Base(readPathPrefix))
			} else {
				lp := strings.ReplaceAll(readPathPrefix, "/", string(filepath.Separator))
				targetDir = filepath.Join(authDirectory, name, filepath.Base(lp))
			}
			if err := os.MkdirAll(targetDir, 0o750); err != nil {
				return fmt.Errorf("error creating auth mount directory: %w", err)
			}
			// LIST
			secret, err := vaultLogical.ListWithContext(ctx, listPath)
			if err != nil {
				return fmt.Errorf("error listing auth mount identities: %w", err)
			}
			if secret == nil {
				log.Warn().Any("secret", secret).Str("listPath", listPath).Msg("LIST path returned empty response, skipping")
				continue
			}
			var listData authListData
			if err := mapstructure.Decode(secret.Data, &listData); err != nil {
				return fmt.Errorf("error decoding auth mount LIST response: %w", err)
			}
			// GET
			var eg errgroup.Group
			eg.SetLimit(5)
			for i := range listData.Keys {
				key := listData.Keys[i]
				eg.Go(func() error {
					getPath := readPathPrefix + key
					log.Debug().Str("getPath", getPath).Msg("reading remote auth principal")
					secret, err := vaultLogical.ReadWithContext(ctx, getPath)
					if err != nil {
						return fmt.Errorf("error reading auth prinicpal: %w", err)
					}
					var getData authPrincipalData
					if err := mapstructure.Decode(secret.Data, &getData); err != nil {
						return fmt.Errorf("error decoding auth mount GET response: %w", err)
					}
					path := filepath.Join(targetDir, key)
					f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
					if err != nil {
						return fmt.Errorf("error opening auth prinicpal file for writing: %w", err)
					}
					defer f.Close()
					enc := json.NewEncoder(f)
					enc.SetIndent("", "  ") // 2 spaces
					if err := enc.Encode(getData); err != nil {
						return fmt.Errorf("error encoding auth prinicpal GET data: %w", err)
					}
					return nil
				})
			}
			if err := eg.Wait(); err != nil {
				return err
			}
			mountPrincipalCount += len(listData.Keys)
		}
		log.Info().Str("mount", "auth/"+name).Int("count", mountPrincipalCount).Msg("downloaded all auth principals")
	}
	return nil
}

func DownloadPolicies(ctx context.Context, vc *vault.Client, policyDirectory string) error {
	vaultSys := vc.Sys()
	policyNames, err := vaultSys.ListPoliciesWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error listing Vault policies: %w", err)
	}
	if err := os.MkdirAll(policyDirectory, 0o755); err != nil {
		return fmt.Errorf("error creating directory: %w", err)
	}
	var eg errgroup.Group
	eg.SetLimit(5)
	for i := range policyNames {
		policyName := policyNames[i]
		eg.Go(func() error {
			log.Debug().Str("policy", policyName).Msg("downloading policy")
			hclData, err := vaultSys.GetPolicyWithContext(ctx, policyName)
			if err != nil {
				return fmt.Errorf("error reading policy: %w", err)
			}
			// TODO: find out if this is a decent Windows SACL
			err = os.WriteFile(
				filepath.Join(policyDirectory, policyName),
				[]byte(hclData),
				0o640,
			)
			if err != nil {
				return fmt.Errorf("error writing Vault policy to file: %w", err)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	log.Info().Int("count", len(policyNames)).Msg("downloaded all policies")
	// delete anything extraenous
	justDownloadedPolicyNames := make(map[string]bool, len(policyNames))
	for _, name := range policyNames {
		justDownloadedPolicyNames[name] = true
	}
	entries, err := os.ReadDir(policyDirectory)
	if err != nil {
		return fmt.Errorf("error reading policy directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !justDownloadedPolicyNames[entry.Name()] {
			toRemove := filepath.Join(policyDirectory, entry.Name())
			log.Info().Str("path", toRemove).Msg("removing extraneous file path")
			if err := os.Remove(toRemove); err != nil {
				return fmt.Errorf("error removing extraneous file path '%s': %w", toRemove, err)
			}
		}
	}
	return nil
}
