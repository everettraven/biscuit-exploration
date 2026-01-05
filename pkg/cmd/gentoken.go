package cmd

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/spf13/cobra"
)

func NewGenTokenCommand() *cobra.Command {
	return &cobra.Command{
		Use: "gentoken",
		RunE: func(cmd *cobra.Command, args []string) error {
			bytes, err := os.ReadFile("biscuit-key.pem")
			if err != nil {
				return fmt.Errorf("reading private key from file: %w", err)
			}

			block, _ := pem.Decode(bytes)

			privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("parsing private key: %w", err)
			}

			privKey, ok := privKeyInterface.(ed25519.PrivateKey)
			if !ok {
				return errors.New("biscuit token generation requires a ed25519 private key")
			}

			builder := biscuit.NewBuilder(privKey)

			authority, err := parser.FromStringBlock(`
				k8s:userinfo:username("everettraven");
				k8s:userinfo:group("one");
				k8s:userinfo:group("two");
			`)
			if err != nil {
				return fmt.Errorf("parsing authority block: %w", err)
			}

			err = builder.AddBlock(authority)
			if err != nil {
				return fmt.Errorf("adding authority block: %w", err)
			}

			b, err := builder.Build()
			if err != nil {
				return fmt.Errorf("failed to build biscuit: %v", err)
			}

			token, err := b.Serialize()
			if err != nil {
				return fmt.Errorf("failed to serialize biscuit: %v", err)
			}

			fmt.Print(base64.URLEncoding.EncodeToString(token))

			return nil
		},
	}
}
