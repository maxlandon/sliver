package db

import (
	"context"

	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/db/ent"
	"github.com/bishopfox/sliver/server/log"
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
	if err := client.Schema.Create(context.Background()); err != nil {
		sqlLog.Errorf("failed creating schema resources: %v", err)
		return nil, err
	}
	return client, nil
}
