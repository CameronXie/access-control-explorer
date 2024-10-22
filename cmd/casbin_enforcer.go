//go:build casbin

package main

import (
	"fmt"
	"log/slog"
	"os"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	_ "github.com/go-sql-driver/mysql"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker/casbin"
	"github.com/CameronXie/access-control-explorer/internal/enforcer"
)

const (
	MysqlUserEnv = "MYSQL_USER"
	MysqlPassEnv = "MYSQL_PASSWORD"
	MysqlHostEnv = "MYSQL_HOST"
	MysqlPortEnv = "MYSQL_PORT"
)

// getConfig returns a string representation of the Casbin configuration model for request, policy, role definitions,
// policy effect, and matchers.
func getConfig() string {
	return `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
}

// getMysqlDSN constructs a MySQL Data Source Name (DSN) from environment variables and returns it as a string.
func getMysqlDSN() string {
	mysqlUser := os.Getenv("MYSQL_USER")
	mysqlPass := os.Getenv("MYSQL_PASSWORD")
	mysqlHost := os.Getenv("MYSQL_HOST")
	mysqlPort := os.Getenv("MYSQL_PORT")
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPass, mysqlHost, mysqlPort)
}

// newPolicyRetriever initializes a new gormadapter.Adapter connected to a MySQL database and adds default policies and grouping.
func newPolicyRetriever() (*gormadapter.Adapter, error) {
	a, err := gormadapter.NewAdapter("mysql", getMysqlDSN())
	if err != nil {
		return nil, err
	}

	if err := a.AddPolicy("p", "p", []string{"admin", "/api/resources", "get"}); err != nil {
		return nil, err
	}

	if err := a.AddPolicy("g", "g", []string{"user1@example.com", "admin"}); err != nil {
		return nil, err
	}

	return a, nil
}

// newEnforcer initializes a new instance of Enforcer with the provided decision maker and policy repository configurations.
func newEnforcer(logger *slog.Logger) (enforcer.Enforcer, error) {
	logger.Info("initializing enforcer with Casbin")

	policyRetriever, err := newPolicyRetriever()
	if err != nil {
		return nil, err
	}

	decisionMaker, err := casbin.NewDecisionMaker(getConfig(), policyRetriever)
	if err != nil {
		return nil, err
	}

	return enforcer.NewEnforcer(decisionMaker), nil
}
