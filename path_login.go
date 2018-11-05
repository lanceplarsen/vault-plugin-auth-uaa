package cfauth

import (
	"context"
	"errors"
	"fmt"
	//"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
	//"gopkg.in/square/go-jose.v2/jwt"
	"encoding/json"
)

type CCResponse struct {
	Resources    []Resource `json:"resources"`
	TotalResults int        `json:"total_results"`
}

type Resource struct {
	Metadata Metadata `json:"metadata"`
	Entity   Entity   `json:"entity"`
}

type Metadata struct {
	Guid string `json:"guid"`
}

type Entity struct {
	Name             string `json:"name"`
	OrganizationGuid string `json:"organization_guid"`
}

func pathLogin(b *cfAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `login$`,
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "The role to log in against.",
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: "The signed CF JWT to validate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLogin,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *cfAuthBackend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("jwt").(string)
	if len(token) == 0 {
		return logical.ErrorResponse("missing token"), nil
	}

	roleName := d.Get("role").(string)
	if len(roleName) == 0 {
		return logical.ErrorResponse("missing role"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role could not be found"), nil
	}

	if req.Connection != nil && !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.BoundCIDRs) {
		return logical.ErrorResponse("request originated from invalid CIDR"), nil
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}


	var claims struct {
		UserName string `json:"user_name"`
		UserID   string `json:"user_id"`
	}

		provider, err := b.getProvider(ctx, config)
		if err != nil {
			return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
		}

		verifier := provider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		})

		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error validating signature: {{err}}", err).Error()), nil
		}

		if err := idToken.Claims(&claims); err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to successfully parse all claims from token: {{err}}", err).Error()), nil
		}

		//Create a client for us to get the CF orgs and spaces
		staticToken := new(oauth2.Token)
		staticToken.AccessToken = token
		client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(staticToken))

		//Orgs
		var orgs CCResponse
		orgsResp, err := client.Get(fmt.Sprintf("%s/v2/users/%s/organizations", config.APIURL, claims.UserID))
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to retrieve CF orgs: {{err}}", err).Error()), nil
		}
		err = json.NewDecoder(orgsResp.Body).Decode(&orgs)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to parse CF orgs: {{err}}", err).Error()), nil
		}

		//Get the spaces
		var spaces CCResponse
		spacesResp, err := client.Get(fmt.Sprintf("%s/v2/users/%s/spaces", config.APIURL, claims.UserID))
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to retrieve CF spaces: {{err}}", err).Error()), nil
		}
		err = json.NewDecoder(spacesResp.Body).Decode(&spaces)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to parse CF spaces: {{err}}", err).Error()), nil
		}

		var guids []string
		for _, resource := range orgs.Resources {
			guids = append(guids, resource.Metadata.Guid)
		}
		for _, resource := range spaces.Resources {
			guids = append(guids, resource.Metadata.Guid)
		}

		var found bool
		for _, v := range role.BoundGUIDs {
			if strutil.StrListContains(guids, v) {
				found = true
				break
			}
		}
		if !found {
			return logical.ErrorResponse("Could not find any matching CF GUIDs"), nil
		}

	//Get our user metadata
	userName := claims.UserName
	userID := claims.UserID

	var groupAliases []*logical.Alias

	resp := &logical.Response{
		Auth: &logical.Auth{
			Policies:    role.Policies,
			DisplayName: userName,
			Period:      role.Period,
			NumUses:     role.NumUses,
			Alias: &logical.Alias{
				Name: userName,
			},
			GroupAliases: groupAliases,
			InternalData: map[string]interface{}{
				"role": roleName,
			},
			Metadata: map[string]string{
				"role":    roleName,
				"user_id": userID,
				"user_name": userName,
			},
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       role.TTL,
				MaxTTL:    role.MaxTTL,
			},
			BoundCIDRs: role.BoundCIDRs,
		},
	}

	return resp, nil
}

func (b *cfAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %s during renewal: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TTL
	resp.Auth.MaxTTL = role.MaxTTL
	resp.Auth.Period = role.Period
	return resp, nil
}

const (
	pathLoginHelpSyn = `
	Authenticates to Vault using a CF JWT token.
	`
	pathLoginHelpDesc = `
Authenticates CF JWTs.
`
)
