package rules
import data.data

# Below is the desired result given the input and the data
# {
#   "result": [
#     "Policy_1",
#     "Policy_2"
#   ]
# }

# A policy key belongs to the set "result" if...
result[policy_key] {
	# for some policy key...
    some policy_key
    # there is a role value in the policy data roles array...
    # that matches a role value in the input roles array
    data.policies[policy_key].roles[_] == input.roles[_]
}

# This is an example of a rule that generates a Set.
# For more info see: 
# * Generating Sets in the OPA docs: https://www.openpolicyagent.org/docs/latest/policy-language/#generating-sets
# * Partial Set Rules under Section 5 of the OPA Rego course in the Styra Academy: https://academy.styra.com/courses/opa-rego
