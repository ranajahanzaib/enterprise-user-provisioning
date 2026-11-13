package scim

import "time"

const (
	CoreUser             = "urn:ietf:params:scim:schemas:core:2.0:User"
	CoreGroup            = "urn:ietf:params:scim:schemas:core:2.0:Group"
	EnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	ErrorSchema          = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
	Version      string    `json:"version,omitempty"`
}
type User struct {
	Schemas           []string       `json:"schemas"`
	ID                string         `json:"id,omitempty"`
	ExternalID        string         `json:"externalId,omitempty"`
	UserName          string         `json:"userName"`
	Active            *bool          `json:"active,omitempty"`
	Name              Name           `json:"name,omitempty"`
	DisplayName       string         `json:"displayName,omitempty"`
	Emails            []Email        `json:"emails,omitempty"`
	Title             string         `json:"title,omitempty"`
	Department        string         `json:"department,omitempty"`
	UserType          string         `json:"userType,omitempty"`
	PreferredLanguage string         `json:"preferredLanguage,omitempty"`
	Enterprise        EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Groups            []Member       `json:"groups,omitempty"`
	Meta              Meta           `json:"meta,omitempty"`
}
type EnterpriseUser struct {
	EmployeeNumber string  `json:"employeeNumber,omitempty"`
	Organization   string  `json:"organization,omitempty"`
	Division       string  `json:"division,omitempty"`
	CostCenter     string  `json:"costCenter,omitempty"`
	Manager        Manager `json:"manager,omitempty"`
}
type Manager struct {
	Value       string `json:"value,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Ref         string `json:"$ref,omitempty"`
}
type Member struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        Meta     `json:"meta,omitempty"`
}
type List struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}
type Error struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}
