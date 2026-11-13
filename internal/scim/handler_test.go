package scim

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFilterSQL(t *testing.T) {
	got, args, err := filterSQL(`userName eq "alex@example.test"`, "username", "external_id", "id")
	if err != nil {
		t.Fatal(err)
	}
	if got != " AND (lower(username::text)=lower($2))" || len(args) != 1 || args[0] != "alex@example.test" {
		t.Fatalf("unexpected parameterized filter: %q %#v", got, args)
	}
}
func TestFilterOperatorsAndParameterization(t *testing.T) {
	columns := map[string]filterColumn{"displayName": {"display_name", false}, "externalId": {"external_id", true}}
	got, args, err := compileFilter(`displayName co "Ops and Finance" and externalId sw "north-"`, columns, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != "Ops and Finance" || args[1] != "north-" {
		t.Fatalf("bad filter args: %#v", args)
	}
	if strings.Contains(got, "Ops") || strings.Contains(got, "north-") {
		t.Fatalf("filter values were concatenated into SQL: %s", got)
	}
}
func TestFilterRejectsUnsupportedOrMalformedExpression(t *testing.T) {
	columns := map[string]filterColumn{"userName": {"username", false}, "id": {"id::text", true}}
	for _, f := range []string{`userName ne "alex"`, `unknown eq "x"`, `userName eq "x" OR 1=1`, `userName eq alex`, `userName co "unterminated`, `userName eq "x" or id eq "y"`} {
		if _, _, err := compileFilter(f, columns, 2); err == nil {
			t.Errorf("accepted unsupported filter %q", f)
		}
	}
}
func TestPageDefaultsAndMaximum(t *testing.T) {
	r := httptest.NewRequest("GET", "/scim/v2/Users?startIndex=0&count=10000", nil)
	start, count := page(r)
	if start != 1 || count != 200 {
		t.Fatalf("unexpected page values: %d/%d", start, count)
	}
}

func TestDiscoveryDoesNotAdvertiseUnsupportedBulkOrSorting(t *testing.T) {
	cfg := serviceProviderConfig()
	bulk := cfg["bulk"].(map[string]any)
	sort := cfg["sort"].(map[string]any)
	if bulk["supported"] != false || sort["supported"] != false {
		t.Fatal("unsupported SCIM capabilities were advertised")
	}
	if len(schemas()) != 3 {
		t.Fatalf("expected core user, group, and enterprise schemas; got %d", len(schemas()))
	}
}
func TestMemberReferenceMustBeTenantResourceShape(t *testing.T) {
	base := "https://scim.example.test"
	for _, m := range []Member{{Value: "123", Type: "User", Ref: base + "/scim/v2/Users/123"}, {Value: "123", Type: "user"}} {
		if !validMemberShape(m, base) {
			t.Errorf("rejected valid member reference %#v", m)
		}
	}
	for _, m := range []Member{{Value: "123", Type: "Group"}, {Value: "123", Type: "User", Ref: "https://attacker.test/scim/v2/Users/123"}, {Type: "User"}} {
		if validMemberShape(m, base) {
			t.Errorf("accepted invalid member reference %#v", m)
		}
	}
}
