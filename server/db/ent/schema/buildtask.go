package schema

import (
	"github.com/facebookincubator/ent"
	"github.com/facebookincubator/ent/schema/field"
	"github.com/google/uuid"
)

// BuildTask holds the schema definition for the BuildTask entity.
type BuildTask struct {
	ent.Schema
}

// Fields of the BuildTask.
func (BuildTask) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("guid", uuid.UUID{}),
	}
}

// Edges of the BuildTask.
func (BuildTask) Edges() []ent.Edge {
	return nil
}
