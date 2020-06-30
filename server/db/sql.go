package db

import (
	"context"

	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/db/ent"
	"github.com/bishopfox/sliver/server/db/ent/migrate"
	"github.com/bishopfox/sliver/server/log"

	// Always include SQLite
	_ "github.com/mattn/go-sqlite3"
)

var (
	sqlLog = log.NamedLogger("db", "sql")
)

// Client - Initialize the db client
func Client() (*ent.Client, error) {
	config := configs.GetDatabaseConfig()
	dsn, err := config.DSN()
	if err != nil {
		return nil, err
	}
	client, err := ent.Open(config.Dialect, dsn)
	if err != nil {
		sqlLog.Errorf("failed opening connection to sqlite: %v", err)
		return nil, err
	}
	defer client.Close()
	// run the auto migration tool.
	ctx := context.Background()
	if err := client.Schema.Create(ctx, migrate.WithGlobalUniqueID(true)); err != nil {
		sqlLog.Errorf("failed creating schema resources: %v", err)
		return nil, err
	}
	return client, nil
}
