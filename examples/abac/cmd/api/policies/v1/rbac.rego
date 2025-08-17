package abac.subject

# RBAC subject evaluation: finds an applicable permission for the subject.
# On Permit, returns cache advice and an audit obligation.
result := r if {
	some role in input.environment.role_hierarchy.descendants
	some permission in input.environment.role_permissions[role]
	is_permission_applicable(permission, input)

	r = {
		"decision": "Permit",
		"status": {"code": "OK"},
		"advices": [{
			"id": "cache_hint",
			"attributes": {"ttl_seconds": 30},
		}],
		"obligations": [{
			"id": "audit_logging",
			"attributes": {
				"level": "INFO",
				"message": sprintf("permit: subject=%s/%s action=%s resource=%s/%s", [input.subject.type, input.subject.id, input.action.id, input.resource.type, input.resource.id]),
			},
		}],
	}
}

# Permission matches action/resource and all conditions are satisfied.
is_permission_applicable(permission, access_context) if {
	permission.action == access_context.action.id
	permission.resource == access_context.resource.type

	all_conditions_satisfied(object.get(permission, "conditions", {}), access_context)
}

# No conditions means satisfied.
all_conditions_satisfied(conditions, _) if {
	count(conditions) == 0
}

# At least one condition must be satisfied (OR semantics across conditions).
all_conditions_satisfied(conditions, access_context) if {
	some condition in conditions
	is_condition_satisfied(condition, access_context)
}

# Evaluate a single condition.
is_condition_satisfied(condition, access_context) if {
	actual_value = access_context.resource.attributes[condition.attribute_key]
	expected_value = resolve_condition_attribute_value(condition.attribute_value, access_context)
	apply_operator(condition.operator, actual_value, expected_value)
}

# Supported operators.
apply_operator(operator, actual_value, expected_value) if {
	operator == "equals"
	actual_value == expected_value
}

# Resolve ${...} references from access context; fallback to literal.
resolve_condition_attribute_value(attribute_value, access_context) := r if {
	matches := regex.find_all_string_submatch_n(`^\${([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)}$`, attribute_value, 1)
	count(matches) > 0
	r := object.get(access_context, split(matches[0][1], "."), "")
} else := attribute_value
