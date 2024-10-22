//go:build !casbin || opa

package main

import (
	"log/slog"

	"github.com/CameronXie/access-control-explorer/internal/enforcer"

	pdp "github.com/CameronXie/access-control-explorer/internal/decisionmaker/opa"
	pip "github.com/CameronXie/access-control-explorer/internal/infoprovider/opa"
	prp "github.com/CameronXie/access-control-explorer/internal/policyretriever/opa"
)

// getPolicy returns a hardcoded Rego policy that defines role-based access control (RBAC) rules for the application.
func getPolicy() string {
	return `
package rbac

role_permissions := {
    "admin": [{"action": "get",  "resource": "/api/resources"}],
}

default allow = false

allow {
    # for each role in that list
    r := input.roles[_]
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "resource": input.resource}
}
`
}

// newEnforcer initializes a new enforcer with the specified logger and returns an Enforcer instance and an error if any occurs.
func newEnforcer(logger *slog.Logger) (enforcer.Enforcer, error) {
	logger.Info("initializing enforcer with OPA")

	decisionMaker := pdp.NewDecisionMaker(
		prp.NewHardcodedPolicyRetriever(getPolicy()),
		pip.NewHardcodedInfoProvider(map[string][]string{
			"user1@example.com": {"admin"},
			"user2@example.com": {"guest"},
		}),
		"data.rbac.allow",
	)

	return enforcer.NewEnforcer(decisionMaker), nil
}
