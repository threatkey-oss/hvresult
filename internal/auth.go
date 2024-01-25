package internal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/consts"
)

type AuthKind int

const (
	Token AuthKind = iota
	TokenAccessor
	RolePathMaybe
)

func (a AuthKind) String() string {
	switch a {
	case Token:
		return "Token"
	case TokenAccessor:
		return "TokenAccessor"
	case RolePathMaybe:
		return "RolePathMaybe"
	}
	return ""
}

// it's a base62 of 24 characters
// see https://github.com/hashicorp/vault/blob/f3a4c01ba9e05850e255406f5bf4bc7f052c3985/vault/token_store.go#L998-L999
var reTokenAccessor = regexp.MustCompile(`^[A-Za-z0-9]{24}$`)

// Guesses what kind of string is coming down the pipe - a token, accessor, role path...
func GuessAuthKind(thing string) (AuthKind, error) {
	for _, prefix := range []string{
		consts.ServiceTokenPrefix,
		consts.BatchTokenPrefix,
		consts.RecoveryTokenPrefix,
		consts.LegacyServiceTokenPrefix,
		consts.LegacyBatchTokenPrefix,
		consts.LegacyRecoveryTokenPrefix,
	} {
		if strings.HasPrefix(thing, prefix) {
			return Token, nil
		}
	}
	if reTokenAccessor.MatchString(thing) {
		return TokenAccessor, nil
	}
	// if it looks a vault path just roll with it
	if strings.Count(thing, "/") > 0 {
		return RolePathMaybe, nil
	}
	return -1, fmt.Errorf("could not guess the auth kind of: '%s'", thing)
}
