package authenticator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func NewBiscuit(pubKeyFile string) *Biscuit {
	return &Biscuit{
		pubKeyFile: pubKeyFile,
	}
}

type Biscuit struct {
	pubKeyFile string
}

func (b *Biscuit) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	decodedToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, false, fmt.Errorf("decoding token: %w", err)
	}

	biscToken, err := biscuit.Unmarshal(decodedToken)
	if err != nil {
		return nil, false, fmt.Errorf("unmarshalling token: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(b.pubKeyFile)
	if err != nil {
		return nil, false, fmt.Errorf("reading public key file: %w", err)
	}

	publicRoot := ed25519.PublicKey(publicKeyBytes)

	authz, err := biscToken.Authorizer(publicRoot)
	if err != nil {
		return nil, false, fmt.Errorf("validating biscuit token: %w", err)
	}

	username, err := usernameFromAuthorizer(authz)
	if err != nil {
		return nil, false, fmt.Errorf("extracting username from token: %w", err)
	}

	groups, err := groupsFromAuthorizer(authz)
	if err != nil {
		return nil, false, fmt.Errorf("extracting groups from token: %w", err)
	}

	user := &userInfo{
		username: username,
		groups:   groups,
		extra: map[string][]string{
			// TODO: probably not all that secure?
			"everettraven.github.io/biscuit": {token},
		},
	}

	return &authenticator.Response{
		User: user,
	}, true, nil
}

func usernameFromAuthorizer(authorizer biscuit.Authorizer) (string, error) {
	rule, err := parser.FromStringRule(`
		username($name) <- k8s:userinfo:username($name)
	`)
	if err != nil {
		return "", fmt.Errorf("creating query rule: %w", err)
	}

	facts, err := authorizer.Query(rule)
	if err != nil {
		return "", fmt.Errorf("querying facts: %w", err)
	}

	for _, fact := range facts {
		if fact.Name == "username" {
			if len(fact.IDs) > 1 {
				return "", fmt.Errorf("username should only have one term")
			}
			return strings.Trim(fact.IDs[0].String(), "\""), nil
		}
	}

	return "", fmt.Errorf("no username found")
}

func groupsFromAuthorizer(authorizer biscuit.Authorizer) ([]string, error) {
	rule, err := parser.FromStringRule(`
		group($name) <- k8s:userinfo:group($name)
	`)
	if err != nil {
		return nil, fmt.Errorf("creating query rule: %w", err)
	}

	facts, err := authorizer.Query(rule)
	if err != nil {
		return nil, fmt.Errorf("querying facts: %w", err)
	}

	groups := []string{}

	for _, fact := range facts {
		if fact.Name == "group" {
			if len(fact.IDs) > 1 {
				return nil, fmt.Errorf("group should only have one term")
			}
			groups = append(groups, strings.Split(strings.Trim(fact.IDs[0].String(), "\""), ",")...)
		}
	}

	return groups, nil
}

type userInfo struct {
	username string
	groups   []string
	uid      string
	extra    map[string][]string
}

func (ui *userInfo) GetName() string {
	return ui.username
}

func (ui *userInfo) GetGroups() []string {
	return ui.groups
}

func (ui *userInfo) GetUID() string {
	return ui.uid
}

func (ui *userInfo) GetExtra() map[string][]string {
	return ui.extra
}
