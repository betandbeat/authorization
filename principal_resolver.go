package authorization

// PrincipalResolver handles the expansion of a user principal to include
// associated roles and group memberships.
type PrincipalResolver interface {
	// ResolvePrincipals takes a principal and returns all associated principals
	// (the original principal plus any roles/groups they belong to)
	ResolvePrincipals(principal Principal) ([]Principal, error)
}

// RoleMapping represents a mapping from user principals to their roles
type RoleMapping struct {
	UserPrincipal Principal   `json:"user_principal"`
	Roles         []Principal `json:"roles"`
}

// ExpandingEvaluator wraps the base evaluator to handle principal expansion
type ExpandingEvaluator struct {
	baseEvaluator Evaluator
	resolver      PrincipalResolver
}

// NewExpandingEvaluator creates a new evaluator that handles principal expansion
func NewExpandingEvaluator(baseEvaluator Evaluator, resolver PrincipalResolver) *ExpandingEvaluator {
	return &ExpandingEvaluator{
		baseEvaluator: baseEvaluator,
		resolver:      resolver,
	}
}

// Evaluate evaluates a request by expanding the principal and checking all associated principals
func (e *ExpandingEvaluator) Evaluate(req Request) (Response, error) {
	// Resolve all principals for the request
	principals, err := e.resolver.ResolvePrincipals(req.Principal)
	if err != nil {
		return Response{
			Effect:  EffectDeny,
			Message: "failed to resolve principals: " + err.Error(),
		}, nil
	}

	// Keep track of all responses for audit purposes
	var responses []Response
	var allowingPrincipal *Principal
	var denyingPrincipal *Principal

	// Evaluate for each principal
	for _, principal := range principals {
		// Create a new request with the expanded principal
		expandedReq := req
		expandedReq.Principal = principal

		response, err := e.baseEvaluator.Evaluate(expandedReq)
		if err != nil {
			return Response{
				Effect:  EffectDeny,
				Message: "evaluation error for principal " + string(principal) + ": " + err.Error(),
			}, nil
		}

		responses = append(responses, response)

		// Track first explicit deny (highest precedence)
		if response.Effect == EffectDeny && denyingPrincipal == nil && response.Decider != nil {
			denyingPrincipal = &principal
		}

		// Track first explicit allow
		if response.Effect == EffectAllow && allowingPrincipal == nil && response.Decider != nil {
			allowingPrincipal = &principal
		}
	}

	// Apply decision logic: explicit deny wins, then explicit allow, then default deny
	if denyingPrincipal != nil {
		return Response{
			Effect:  EffectDeny,
			Message: "access denied for principal " + string(*denyingPrincipal),
			Decider: stringPtr("principal_expansion:" + string(*denyingPrincipal)),
		}, nil
	}

	if allowingPrincipal != nil {
		return Response{
			Effect:  EffectAllow,
			Message: "access allowed for principal " + string(*allowingPrincipal),
			Decider: stringPtr("principal_expansion:" + string(*allowingPrincipal)),
		}, nil
	}

	// Default deny if no explicit decisions found
	return Response{
		Effect:  EffectDeny,
		Message: "no matching statements found for any expanded principal, access denied by default",
	}, nil
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}
