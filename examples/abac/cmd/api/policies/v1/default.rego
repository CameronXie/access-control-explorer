package abac

import data.abac.subject
import data.abac.resource

# Top-level combiner: merges subject and resource results.
# Default: no applicable policy.
default result := {
	"decision": "NotApplicable",
	"status": {
		"code": "PolicyNotFound",
		"message": "no applicable policy was found for this request",
	},
}

# Permit only if both subject and resource permit.
result = subject.result if {
    subject.result.decision == "Permit"
    resource.result.decision == "Permit"
}

# If resource module not present, defer to subject.
result := subject.result if {
    not resource.result
}

# If subject denies (or not permit), return subject result.
result := subject.result if {
    subject.result.decision != "Permit"
}

# If subject module not present, defer to resource.
result := resource.result if {
    not subject.result
}

# If subject permits but resource does not, return resource result.
result := resource.result if {
    subject.result.decision == "Permit"
    resource.result.decision != "Permit"
}
