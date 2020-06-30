package schema

import "github.com/facebookincubator/ent"

// ImplantProfile holds the schema definition for the ImplantProfile entity.
type ImplantProfile struct {
	ent.Schema
}

// Fields of the ImplantProfile.
func (ImplantProfile) Fields() []ent.Field {
	return nil
}

// Edges of the ImplantProfile.
func (ImplantProfile) Edges() []ent.Edge {
	return nil
}
