package system

import rego.v1

default main := {"decision": false}

# Customer access to /api/bar with age restriction for Beer
main := {"decision": true} if {
    input.resource.id == "/api/bar"
    body := json.unmarshal(input.context.data.requestBody)
    body.DrinkName == "Beer"
    
    some role_claim in input.subject.claims
    role_claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    role_claim.Value == "Customer"
    
    some age_claim in input.subject.claims
    age_claim.Type == "age"
    age := to_number(age_claim.Value)
    age >= 16
}

# Customer access to /api/bar for non-alcoholic drinks (no age restriction)
main := {"decision": true} if {
    input.resource.id == "/api/bar"
    body := json.unmarshal(input.context.data.requestBody)
    body.DrinkName == "Fristi"
    
    some role_claim in input.subject.claims
    role_claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    role_claim.Value == "Customer"
}

# Bartender access to /api/managebar (management functions)
main := {"decision": true} if {
    input.resource.id == "/api/managebar"
    some role_claim in input.subject.claims
    role_claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    role_claim.Value == "Bartender"
}

# Bartender access to /api/bar (can also order drinks)
main := {"decision": true} if {
    input.resource.id == "/api/bar"
    some role_claim in input.subject.claims
    role_claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    role_claim.Value == "Bartender"
}
