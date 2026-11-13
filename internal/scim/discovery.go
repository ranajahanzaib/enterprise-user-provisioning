package scim

import "strings"

type capability struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations,omitempty"`
	MaxPayloadSize int  `json:"maxPayloadSize,omitempty"`
}

func serviceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":                 capability{Supported: true, MaxOperations: 100, MaxPayloadSize: 1048576},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Tenant-scoped SCIM bearer token", "specUri": "https://www.rfc-editor.org/rfc/rfc6750", "primary": true}},
	}
}
func resourceTypes(base string) []map[string]any {
	return []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "description": "Provisioned user", "schema": CoreUser, "schemaExtensions": []map[string]any{{"schema": EnterpriseUserSchema, "required": false}}, "meta": map[string]string{"location": base + "/scim/v2/ResourceTypes/User", "resourceType": "ResourceType"}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "description": "Provisioning group", "schema": CoreGroup, "meta": map[string]string{"location": base + "/scim/v2/ResourceTypes/Group", "resourceType": "ResourceType"}},
	}
}
func resourceTypeByID(base, id string) (map[string]any, bool) {
	for _, v := range resourceTypes(base) {
		if v["id"] == id {
			return v, true
		}
	}
	return nil, false
}
func schemas() []map[string]any {
	return []map[string]any{
		{"id": CoreUser, "name": "User", "description": "Core User", "attributes": userAttributes()},
		{"id": CoreGroup, "name": "Group", "description": "Core Group", "attributes": groupAttributes()},
		{"id": EnterpriseUserSchema, "name": "EnterpriseUser", "description": "Enterprise User Extension", "attributes": enterpriseAttributes()},
	}
}
func schemaByID(id string) (map[string]any, bool) {
	for _, v := range schemas() {
		if v["id"] == id {
			return v, true
		}
	}
	return nil, false
}
func userAttributes() []map[string]any {
	attrs := []map[string]any{
		attr("userName", "string", true, "readWrite", false), attr("externalId", "string", false, "readWrite", true), attr("active", "boolean", false, "readWrite", false), attr("displayName", "string", false, "readWrite", false), attr("title", "string", false, "readWrite", false), attr("department", "string", false, "readWrite", false), attr("userType", "string", false, "readWrite", false), attr("preferredLanguage", "string", false, "readWrite", false), attr("name", "complex", false, "readWrite", false), attr("emails", "complex", false, "readWrite", false), attr("groups", "complex", false, "readOnly", false), attr("id", "string", false, "readOnly", true), attr("meta", "complex", false, "readOnly", false),
	}
	attrs[0]["uniqueness"] = "server"
	attrs[1]["uniqueness"] = "server"
	attrs[8]["subAttributes"] = []map[string]any{attr("formatted", "string", false, "readWrite", false), attr("givenName", "string", false, "readWrite", false), attr("familyName", "string", false, "readWrite", false)}
	attrs[9]["multiValued"] = true
	attrs[9]["subAttributes"] = []map[string]any{attr("value", "string", true, "readWrite", false), attr("type", "string", false, "readWrite", false), attr("primary", "boolean", false, "readWrite", false)}
	attrs[10]["multiValued"] = true
	return attrs
}
func enterpriseAttributes() []map[string]any {
	return []map[string]any{attr("employeeNumber", "string", false, "readWrite", false), attr("organization", "string", false, "readWrite", false), attr("division", "string", false, "readWrite", false), attr("costCenter", "string", false, "readWrite", false), attr("manager", "complex", false, "readWrite", false)}
}
func groupAttributes() []map[string]any {
	attrs := []map[string]any{attr("displayName", "string", true, "readWrite", false), attr("externalId", "string", false, "readWrite", false), attr("members", "complex", false, "readWrite", false), attr("id", "string", false, "readOnly", true), attr("meta", "complex", false, "readOnly", false)}
	attrs[0]["uniqueness"] = "server"
	attrs[1]["uniqueness"] = "server"
	attrs[2]["multiValued"] = true
	attrs[2]["subAttributes"] = []map[string]any{attr("value", "string", true, "readWrite", true), attr("type", "string", false, "readWrite", false), attr("display", "string", false, "readOnly", false), attr("$ref", "reference", false, "readOnly", true)}
	return attrs
}
func attr(name, typ string, required bool, mutability string, caseExact bool) map[string]any {
	return map[string]any{"name": name, "type": typ, "multiValued": typ == "complex" && strings.HasSuffix(name, "s"), "required": required, "caseExact": caseExact, "mutability": mutability, "returned": "default", "uniqueness": "none"}
}
