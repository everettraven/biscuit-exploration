package server

import (
	"net/http"

	localauthenticator "github.com/everettraven/biscuit/pkg/authenticator"
	localauthorizer "github.com/everettraven/biscuit/pkg/authorizer"
	"github.com/everettraven/biscuit/pkg/handlers"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func New() *Instance {
	return &Instance{}
}

type Instance struct {
	addr               string
	tokenAuthenticator authenticator.Token
	authorizer         authorizer.Authorizer
	publicKeyFile      string
}

func (i *Instance) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&i.addr, "addr", "0.0.0.0:8080", "specifies the address in which the server should listen for incoming requests")
	fs.StringVar(&i.publicKeyFile, "public-key-file", "biscuit-key.pub", "path to file containing public key for verification of biscuit tokens")
}

func (i *Instance) Serve() error {
	mux := http.NewServeMux()

	i.tokenAuthenticator = localauthenticator.NewBiscuit(i.publicKeyFile)
	i.authorizer = localauthorizer.NewBiscuit(i.publicKeyFile)

	mux.Handle("/authenticate", handlers.NewAuthenticate(i.tokenAuthenticator))
	mux.Handle("/authorize", handlers.NewAuthorize(i.authorizer))

	return http.ListenAndServe(i.addr, mux)
}
