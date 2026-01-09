package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/spf13/cobra"
)

func NewAttenuateCommand() *cobra.Command {
	attenuator := attenuator{}
	cmd := &cobra.Command{
		Use: "attenuate",
		RunE: func(cmd *cobra.Command, args []string) error {
			attenuated, err := attenuator.Attenuate()
			if err != nil {
				return err
			}

			fmt.Print(base64.URLEncoding.EncodeToString(attenuated))

			return nil
		},
	}

	cmd.Flags().StringVar(&attenuator.token, "token", "", "sets token for attenuation")
	cmd.Flags().StringArrayVar(&attenuator.resource, "resource", []string{}, "sets resources for attenuation")
	cmd.Flags().StringArrayVar(&attenuator.namespace, "namespace", []string{}, "sets namespaces for attenuation")
	cmd.Flags().StringArrayVar(&attenuator.name, "name", []string{}, "sets names for attenuation")
	cmd.Flags().StringArrayVar(&attenuator.verb, "verb", []string{}, "sets verbs for attenuation")

	return cmd
}

type attenuator struct {
	token     string
	resource  []string
	namespace []string
	name      []string
	verb      []string
}

func (a attenuator) Attenuate() ([]byte, error) {
	decodedToken, err := base64.URLEncoding.DecodeString(a.token)
	if err != nil {
		return nil, fmt.Errorf("decoding token: %w", err)
	}

	token, err := biscuit.Unmarshal(decodedToken)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling token: %w", err)
	}

	checks := []biscuit.Check{}

	if len(a.resource) > 0 {
		var checkString strings.Builder
		checkString.WriteString(fmt.Sprintf("check if k8s:resource(%q)", a.resource[0]))
		for _, res := range a.resource[1:] {
			checkString.WriteString(fmt.Sprintf(" or k8s:resource(%q)", res))
		}

		check, err := parser.FromStringCheck(checkString.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse resource check: %v", err)
		}

		checks = append(checks, check)
	}

	if len(a.namespace) > 0 {
		var checkString strings.Builder
		checkString.WriteString(fmt.Sprintf("check if k8s:namespace(%q)", a.namespace[0]))
		for _, res := range a.namespace[1:] {
			checkString.WriteString(fmt.Sprintf(" or k8s:namespace(%q)", res))
		}

		check, err := parser.FromStringCheck(checkString.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse namespace check: %v", err)
		}

		checks = append(checks, check)
	}

	if len(a.name) > 0 {
		var checkString strings.Builder
		checkString.WriteString(fmt.Sprintf("check if k8s:name(%q)", a.name[0]))
		for _, res := range a.name[1:] {
			checkString.WriteString(fmt.Sprintf(" or k8s:name(%q)", res))
		}

		check, err := parser.FromStringCheck(checkString.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse name check: %v", err)
		}

		checks = append(checks, check)
	}

	if len(a.verb) > 0 {
		var checkString strings.Builder
		checkString.WriteString(fmt.Sprintf("check if k8s:verb(%q)", a.verb[0]))
		for _, res := range a.verb[1:] {
			checkString.WriteString(fmt.Sprintf(" or k8s:verb(%q)", res))
		}

		check, err := parser.FromStringCheck(checkString.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse verb check: %v", err)
		}

		checks = append(checks, check)
	}

	blockBuilder := token.CreateBlock()
	for _, check := range checks {
		blockBuilder.AddCheck(check)
	}

	b2, err := token.Append(rand.Reader, blockBuilder.Build())
	if err != nil {
		return nil, fmt.Errorf("failed to append: %v", err)
	}

	token2, err := b2.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %v", err)
	}

	return token2, nil
}
