package cfauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	//"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

func pathConfig(b *cfAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"uaa_url": {
				Type:        framework.TypeString,
				Description: `PCF base uaa domain.`,
			},
			"api_url": {
				Type:        framework.TypeString,
				Description: `PCF base api domain.`,
			},
			"cf_ca_pem": {
				Type:        framework.TypeString,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate conections to the PCF OIDC Discovery URL. If not set, system certificates are used.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *cfAuthBackend) config(ctx context.Context, s logical.Storage) (*cfConfig, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	if b.cachedConfig != nil {
		return b.cachedConfig, nil
	}

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result := &cfConfig{}
	if entry != nil {
		if err := entry.DecodeJSON(result); err != nil {
			return nil, err
		}
	}

	b.cachedConfig = result

	return result, nil
}

func (b *cfAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"uaa_url":   config.UAAURL,
			"api_url":   config.APIURL,
			"cf_ca_pem": config.CFCAPEM,
		},
	}

	return resp, nil
}

func (b *cfAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &cfConfig{
		UAAURL:  d.Get("uaa_url").(string),
		APIURL:  d.Get("api_url").(string),
		CFCAPEM: d.Get("cf_ca_pem").(string),
	}

	_, err := b.createProvider(config)
	if err != nil {
		return logical.ErrorResponse(errwrap.Wrapf("error checking discovery URL: {{err}}", err).Error()), nil
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *cfAuthBackend) createProvider(config *cfConfig) (*oidc.Provider, error) {
	var certPool *x509.CertPool
	if config.CFCAPEM != "" {
		certPool = x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(config.CFCAPEM)); !ok {
			return nil, errors.New("could not parse 'cf_ca_pem' value successfully")
		}
	}

	tr := cleanhttp.DefaultPooledTransport()
	if certPool != nil {
		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	tc := &http.Client{
		Transport: tr,
	}
	oidcCtx := context.WithValue(b.providerCtx, oauth2.HTTPClient, tc)

	provider, err := oidc.NewProvider(oidcCtx, fmt.Sprintf("%s/oauth/token", config.UAAURL))
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	return provider, nil
}

type cfConfig struct {
	UAAURL  string `json:"uaa_url"`
	APIURL  string `json:"api_url"`
	CFCAPEM string `json:"cf_ca_pem"`
}

const (
	confHelpSyn = `
Configures the CF authentication backend.
`
	confHelpDesc = `
The CF authentication backend validates tokens issued by the UAA server.
`
)
