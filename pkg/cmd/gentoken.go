package cmd

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewGenTokenCommand() *cobra.Command {
	tg := &TokenGenerator{}

	cmd := &cobra.Command{
		Use: "gentoken",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := tg.Generate()
			if err != nil {
				return err
			}

			fmt.Println(token)
			return nil
		},
	}

	tg.AddFlags(cmd.Flags())
	return cmd
}

type TokenGenerator struct {
	username string
	groups   []string
	keyFile  string
}

func (tg *TokenGenerator) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&tg.username, "username", "jane", "set the username to set in the token")
	fs.StringArrayVar(&tg.groups, "groups", []string{}, "set the groups to set in the token")
	fs.StringVar(&tg.keyFile, "private-key-file", "biscuit-key.pem", "set the private key file to use for generating the token")
}

func (tg *TokenGenerator) Generate() (string, error) {
	bytes, err := os.ReadFile(tg.keyFile)
	if err != nil {
		return "", fmt.Errorf("reading private key from file: %w", err)
	}

	block, _ := pem.Decode(bytes)

	privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	privKey, ok := privKeyInterface.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("biscuit token generation requires a ed25519 private key")
	}

	builder := biscuit.NewBuilder(privKey)

	var authorityBlock strings.Builder

	authorityBlock.WriteString(fmt.Sprintf("k8s:userinfo:username(%q);\n", tg.username))

	for _, group := range tg.groups {
		authorityBlock.WriteString(fmt.Sprintf("k8s:userinfo:group(%q);\n", group))
	}

	authority, err := parser.FromStringBlock(authorityBlock.String())
	if err != nil {
		return "", fmt.Errorf("parsing authority block: %w", err)
	}

	err = builder.AddBlock(authority)
	if err != nil {
		return "", fmt.Errorf("adding authority block: %w", err)
	}

	b, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build biscuit: %v", err)
	}

	token, err := b.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize biscuit: %v", err)
	}

	return base64.URLEncoding.EncodeToString(token), nil
}
