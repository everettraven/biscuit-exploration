package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/spf13/cobra"
)

func NewAuthorizeCommand() *cobra.Command {
	authorizer := authorizer{}
	cmd := &cobra.Command{
		Use: "authorize",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authorizer.Authorize()
		},
	}

	cmd.Flags().StringVar(&authorizer.token, "token", "", "sets token for authorization")
	cmd.Flags().StringVar(&authorizer.pubKeyFile, "public-key-file", "biscuit-key.pub", "sets public key file for token verification")
	cmd.Flags().StringVar(&authorizer.resource, "resource", "", "sets resource for authorization")
	cmd.Flags().StringVar(&authorizer.namespace, "namespace", "", "sets namespace for authorization")
	cmd.Flags().StringVar(&authorizer.name, "name", "", "sets name for authorization")
	cmd.Flags().StringVar(&authorizer.verb, "verb", "", "sets verb for authorization")

	return cmd
}

type authorizer struct {
	token      string
	pubKeyFile string
	resource   string
	namespace  string
	name       string
	verb       string
}

func (a authorizer) Authorize() error {
	decodedToken, err := base64.URLEncoding.DecodeString(a.token)
	if err != nil {
		return fmt.Errorf("decoding token: %w", err)
	}

	token, err := biscuit.Unmarshal(decodedToken)
	if err != nil {
		return fmt.Errorf("unmarshalling token: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(a.pubKeyFile)
	if err != nil {
		return fmt.Errorf("reading public key file: %w", err)
	}

	publicRoot := ed25519.PublicKey(publicKeyBytes)

	var blockString strings.Builder

	if a.resource != "" {
		blockString.WriteString(fmt.Sprintf("k8s:resource(%q);\n", a.resource))
	}

	if a.namespace != "" {
		blockString.WriteString(fmt.Sprintf("k8s:namespace(%q);\n", a.namespace))
	}

	if a.name != "" {
		blockString.WriteString(fmt.Sprintf("k8s:name(%q);\n", a.name))
	}

	if a.verb != "" {
		blockString.WriteString(fmt.Sprintf("k8s:verb(%q);\n", a.verb))
	}

	blockString.WriteString("allow if true;\n")

	v1, err := token.Authorizer(publicRoot)
	if err != nil {
		panic(fmt.Errorf("failed to create verifier: %v", err))
	}

	authorizer, err := parser.FromStringAuthorizer(blockString.String())
	if err != nil {
		panic(fmt.Errorf("failed to parse authorizer: %v", err))
	}

	v1.AddAuthorizer(authorizer)

	if err := v1.Authorize(); err != nil {
		fmt.Println("forbidden")
	} else {
		fmt.Println("allowed")
	}

	return nil
}
