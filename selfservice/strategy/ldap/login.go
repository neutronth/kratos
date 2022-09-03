package ldap

import (
	"net/http"
	"time"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlcon"
	"github.com/pkg/errors"
)

var _ login.Strategy = new(Strategy)

func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
}

func (s *Strategy) handleLoginError(w http.ResponseWriter, r *http.Request, f *login.Flow, payload *submitSelfServiceLoginFlowWithLDAPMethodBody, err error) error {
	if f != nil {
		f.UI.Nodes.ResetNodes("ldap_password")
		f.UI.Nodes.SetValueAttribute("ldap_identifier", payload.Identifier)
		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		}
	}

	return err
}

func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, ss *session.Session) (i *identity.Identity, err error) {
	if err := login.CheckAAL(f, identity.AuthenticatorAssuranceLevel1); err != nil {
		return nil, err
	}

	if err := flow.MethodEnabledAndAllowedFromRequest(r, s.ID().String(), s.d); err != nil {
		return nil, err
	}

	var p submitSelfServiceLoginFlowWithLDAPMethodBody
	if err := s.dec.Decode(r, &p,
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.MustHTTPRawJSONSchemaCompiler(loginSchema),
		decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, err)
	}

	if err := flow.EnsureCSRF(s.d, r, f.Type, s.d.Config(r.Context()).DisableAPIFlowEnforcement(), s.d.GenerateCSRFToken, p.CSRFToken); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, err)
	}

	user, groups, err := s.ldapLogin(r.Context(), p.Identifier, p.Password)
	if err != nil {
		return nil, s.handleLoginError(w, r, f, &p, errors.WithStack(schema.NewInvalidCredentialsError()))
	}

	conf, err := s.Config(r.Context())
	if err != nil {
		s.d.Logger().WithError(err).Debug("LDAP Config")
		return nil, err
	}

	shouldRegister := false
	shouldUpdateIdentity := false

	i, _, err = s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), s.ID(), user.DN)
	if err != nil && errors.Is(err, sqlcon.ErrNoRows) {
		shouldRegister = true
	} else if conf.UpdateUserIdentity.Enabled &&
		time.Now().After(i.UpdatedAt.Add(conf.UpdateUserIdentity.RefreshTime.Duration)) {
		shouldUpdateIdentity = true
	}

	switch {
	case shouldRegister:
		aa, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, flow.TypeBrowser)
		if err != nil {
			return nil, err
		}

		if i, err = s.processRegistration(w, r, aa, user, groups); err != nil {
			return nil, err
		}
	case shouldUpdateIdentity:
		traits, err := s.extractIdentity(r.Context(), user, groups)
		if err != nil {
			return nil, err
		}
		i.Traits = identity.Traits(traits)

		return i, s.d.PrivilegedIdentityPool().UpdateIdentity(r.Context(), i)
	}

	return i, nil
}

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, sr *login.Flow) error {
	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	sr.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	sr.UI.SetNode(node.NewInputField("ldap_identifier", nil, node.LDAPGroup, node.InputAttributeTypeText, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeLabelID()))
	sr.UI.SetNode(NewLDAPNode("ldap_password"))
	sr.UI.GetNodes().Append(node.NewInputField("method", "ldap", node.LDAPGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoLogin()))

	return nil
}
