package authorization

import "strings"

// inMemoryPrincipalResolver is an in-memory implementation of PrincipalResolver
// In a real system, this would likely query a user management system or directory service
type inMemoryPrincipalResolver struct {
	roleMappings map[Principal][]Principal
}

// NewInMemoryPrincipalResolver creates a new in-memory principal resolver
func NewInMemoryPrincipalResolver() *inMemoryPrincipalResolver {
	return &inMemoryPrincipalResolver{
		roleMappings: make(map[Principal][]Principal),
	}
}

// AddRoleMapping adds a role mapping for a user
func (r *inMemoryPrincipalResolver) AddRoleMapping(userPrincipal Principal, roles []Principal) {
	r.roleMappings[userPrincipal] = roles
}

// ResolvePrincipals expands a principal to include all associated roles
func (r *inMemoryPrincipalResolver) ResolvePrincipals(principal Principal) ([]Principal, error) {
	// Always include the original principal
	principals := []Principal{principal}

	// Only expand if this is a user principal (starts with "users/")
	if strings.HasPrefix(string(principal), "users/") {
		if roles, exists := r.roleMappings[principal]; exists {
			principals = append(principals, roles...)
		}
	}

	return principals, nil
}
