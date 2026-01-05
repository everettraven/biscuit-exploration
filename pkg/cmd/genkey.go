package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewGenKeyCommand() *cobra.Command {
	return &cobra.Command{
		Use: "genkey",
		RunE: func(cmd *cobra.Command, args []string) error {
			rng := rand.Reader
			publicKey, privateRoot, err := ed25519.GenerateKey(rng)
			if err != nil {
				return fmt.Errorf("generating ed25519 keys: %w", err)
			}

			privBytes, err := x509.MarshalPKCS8PrivateKey(privateRoot)
			if err != nil {
				return fmt.Errorf("marshalling private key: %w", err)
			}

			privPem := pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY",
				Bytes: privBytes,
			})

			err = os.WriteFile("biscuit-key.pem", privPem, 0600)
			if err != nil {
				return fmt.Errorf("writing private key to file: %w", err)
			}

			err = os.WriteFile("biscuit-key.pub", publicKey, 0644)
			if err != nil {
				return fmt.Errorf("writing public key to file: %w", err)
			}

			return nil
		},
	}
}
