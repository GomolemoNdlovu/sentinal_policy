package terraform.azure.tags
# Required tags
required_tags = {"environment", "owner", "cost_center"}
# Deny if any required tag is missing
deny[msg] {
 resource := input.resource_changes[_]
 # Only check resources being created or updated
 action := resource.change.actions[_]
 action == "create" or action == "update"
 # Only Azure resources
 startswith(resource.type, "azurerm_")
 tags := resource.change.after.tags
 # Handle missing tags block
 tags == null
 msg := sprintf("Resource '%s' has no tags defined", [resource.address])
}
deny[msg] {
 resource := input.resource_changes[_]
 action := resource.change.actions[_]
 action == "create" or action == "update"
 startswith(resource.type, "azurerm_")
 tags := resource.change.after.tags
 # Find missing tags
 missing := required_tags - object.keys(tags)
 count(missing) > 0
 msg := sprintf(
   "Resource '%s' missing required tags: %v",
   [resource.address, missing]
 )
}
