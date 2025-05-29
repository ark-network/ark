.PHONY: build clean cov help intergrationtest lint run run-mutinynet test vet migrate sqlc

define setup_env
    $(eval include $(1))
    $(eval export)
endef

## build: build for all platforms
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## cov: generates coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./...

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## intergrationtest: runs integration tests
integrationtest:
	@echo "Running integration tests..."
	@go test -v -count 1 -timeout 500s github.com/ark-network/ark/server/test/e2e

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## run: run arkd in regtest
run: clean
	@echo "Running arkd in regtest"
	$(call setup_env, envs/regtest.env)
	go run ./cmd/arkd

## run-neutrino: run arkd in mutinynet
run-mutinynet: clean
	@echo "Running arkd in mutinynet"
	$(call setup_env, envs/regtest.env)
	go run ./cmd/arkd

## test: runs unit and component tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race ./internal/...
	@find ./pkg -name go.mod -execdir go test -v -count=1 -race ./... \;

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## migrate: creates sqlite migration file(eg. make FILE=init mig_file)
migrate:
	@docker run --rm -v ./internal/infrastructure/db/sqlite/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	@docker run --rm -v ./internal/infrastructure/db/sqlite:/src -w /src sqlc/sqlc generate

#### Postgres database ####
# pg: starts postgres db inside docker container
pg:
	@docker run --name ark-pg -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=ark-db -d postgres

# droppg: stop and remove postgres container
droppg:
	@docker stop ark-pg
	@docker rm ark-pg

# createdb: create db inside docker container
createdb:
	@docker exec ark-pg createdb --username=root --owner=root ark-db

# dropdb: drops db inside docker container
dropdb:
	@docker exec ark-pg dropdb ark-db

# createtestdb: create test db inside docker container
createtestdb:
	@docker exec ark-pg createdb --username=root --owner=root ark-db-test

# droptestdb: drops test db inside docker container
droptestdb:
	@docker exec ark-pg dropdb ark-db-test

# recreatetestdb: drops and creates test db
recreatetestdb: droptestdb createtestdb

# pgcreatetestdb: starts docker container and creates test db, used in CI
pgcreatetestdb:
	@chmod u+x ./scripts/create_testdb
	@./scripts/create_testdb

# psql: connects to postgres terminal running inside docker container
psql:
	@docker exec -it ark-pg psql -U root -d ark-db -c "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');" \
	&& docker exec -it ark-pg psql -U root -d ark-db

# pgmigrate: creates pg migration file (e.g. make FILE=init pgmigrate)
pgmigrate:
	@migrate create -ext sql -dir ./internal/infrastructure/db/postgres/migration/ $(FILE)

# pgmigrate-up: applies all Postgres migrations to the running ark-pg container
pgmigrate-up: dropdb createdb
	@docker run --rm \
	  -v $(PWD)/internal/infrastructure/db/postgres/migration:/migrations \
	  --network host \
	  migrate/migrate \
	  -path=/migrations \
	  -database "postgres://root:secret@localhost:5432/ark-db?sslmode=disable" up

# pgsqlc: generate sql code for postgres
pgsqlc:
	@cd internal/infrastructure/db/postgres; sqlc generate