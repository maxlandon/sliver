package schema

import (
	"github.com/facebookincubator/ent"
	"github.com/facebookincubator/ent/schema/edge"
	"github.com/facebookincubator/ent/schema/field"
)

// BuildTask holds the schema definition for the BuildTask entity.
type BuildTask struct {
	ent.Schema
}

// Fields of the BuildTask.
func (BuildTask) Fields() []ent.Field {
	return []ent.Field{
		field.Time("Started"),
		field.Time("Completed"),
	}
}

// Edges of the BuildTask.
func (BuildTask) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("Implant", Implant.Type),
		edge.To("ImplantProfile", ImplantProfile.Type),
	}
}
