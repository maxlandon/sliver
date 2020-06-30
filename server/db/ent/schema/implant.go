package schema

import (
	"github.com/facebookincubator/ent"
	"github.com/facebookincubator/ent/schema/field"
	"github.com/google/uuid"
)

// Implant holds the schema definition for the Implant entity.
type Implant struct {
	ent.Schema
}

// Fields of the Implant.
func (Implant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("ID", uuid.UUID{}),

		field.String("GOOS"),
		field.String("GOARCH"),

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
	}
}

// Edges of the Implant.
func (Implant) Edges() []ent.Edge {
	return nil
}
