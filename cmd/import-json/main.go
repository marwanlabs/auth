// Command import-json validates and imports a JSON store into PostgreSQL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"authserver/internal/pg"
)

func main() {
	path := flag.String("data", "data/store.json", "path to the JSON store")
	flag.Parse()
	cfg, err := pg.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if cfg == nil {
		log.Fatal("AUTH_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, err := pg.Connect(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if _, err := pg.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	report, err := pg.ImportJSON(ctx, db, *path)
	encoded, encodeErr := json.MarshalIndent(report, "", "  ")
	if encodeErr == nil {
		fmt.Println(string(encoded))
	}
	if err != nil {
		log.Fatal(err)
	}
}
