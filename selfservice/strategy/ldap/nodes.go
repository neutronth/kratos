package ldap

import (
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
)

func NewLDAPNode(name string) *node.Node {
	return node.NewInputField(name, nil, node.LDAPGroup,
		node.InputAttributeTypePassword,
		node.WithRequiredInputAttribute).
		WithMetaLabel(text.NewInfoNodeInputPassword())
}
