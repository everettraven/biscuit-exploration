package authorizer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func NewBiscuit(publicKeyFile string) *Biscuit {
	return &Biscuit{
		pubKeyFile: publicKeyFile,
	}
}

type Biscuit struct {
	pubKeyFile string
}

func (b *Biscuit) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	extras := attrs.GetUser().GetExtra()
	token, ok := extras["everettraven.github.io/biscuit"]
	if !ok {
		return authorizer.DecisionNoOpinion, "", nil
	}

	decodedToken, err := base64.URLEncoding.DecodeString(token[0])
	if err != nil {
		return authorizer.DecisionNoOpinion, "", fmt.Errorf("decoding token: %w", err)
	}

	biscToken, err := biscuit.Unmarshal(decodedToken)
	if err != nil {
		return authorizer.DecisionNoOpinion, "", fmt.Errorf("unmarshalling token: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(b.pubKeyFile)
	if err != nil {
		return authorizer.DecisionNoOpinion, "", fmt.Errorf("reading public key file: %w", err)
	}

	publicRoot := ed25519.PublicKey(publicKeyBytes)

	var blockString strings.Builder

	if attrs.GetResource() != "" {
		blockString.WriteString(fmt.Sprintf("k8s:resource(%q);\n", attrs.GetResource()))
	}

	if attrs.GetNamespace() != "" {
		blockString.WriteString(fmt.Sprintf("k8s:namespace(%q);\n", attrs.GetNamespace()))
	}

	if attrs.GetName() != "" {
		blockString.WriteString(fmt.Sprintf("k8s:name(%q);\n", attrs.GetName()))
	}

	if attrs.GetVerb() != "" {
		blockString.WriteString(fmt.Sprintf("k8s:verb(%q);\n", attrs.GetVerb()))
	}

	blockString.WriteString("allow if true;\n")

	authz, err := biscToken.Authorizer(publicRoot)
	if err != nil {
		return authorizer.DecisionNoOpinion, "", fmt.Errorf("validating biscuit token: %w", err)
	}

	parsedAuthorizer, err := parser.FromStringAuthorizer(blockString.String())
	if err != nil {
		panic(fmt.Errorf("failed to parse authorizer: %v", err))
	}

	authz.AddAuthorizer(parsedAuthorizer)

	err = authz.Authorize()
	if err != nil {
		return authorizer.DecisionDeny, err.Error(), nil
	}

	return authorizer.DecisionNoOpinion, "", nil
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
			return fact.IDs[0].String(), nil
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
			groups = append(groups, fact.IDs[0].String())
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
