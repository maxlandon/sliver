package schema

import (
	"github.com/facebookincubator/ent"
	"github.com/facebookincubator/ent/schema/field"
)

// ImplantProfile holds the schema definition for the ImplantProfile entity.
type ImplantProfile struct {
	ent.Schema
}

// Fields - of the ImplantProfile.
func (ImplantProfile) Fields() []ent.Field {
	return []ent.Field{
		field.String("GOOS"),
		field.String("GOARCH"),
		field.String("Name"),
		field.String("ECC_ClientCert"),
		field.String("ECC_ClientKey"),
		field.String("RSA_Cert"),
		field.Bool("Debug"),
		field.Bool("ObfuscateSymbols"),
		field.Uint32("ReconnectInterval"),
		field.Uint32("MaxConnectionErrors"),

		field.Bool("LimitDomainJoined"),
		field.Int64("LimitDatetime"),
		field.String("LimitHostname"),
		field.String("LimitUsername"),

		field.Int("OutputFormat"),
		field.String("FileName"),

		field.Int64("BuildTimeout")
	}
}

// Edges of the ImplantProfile.
func (ImplantProfile) Edges() []ent.Edge {
	return nil
}
