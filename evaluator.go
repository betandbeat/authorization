package authorization

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
)

type Evaluator interface {
	Evaluate(req Request) (Response, error)
}

type evaluator struct {
	storage Storage
}

func NewEvaluator(storage Storage) Evaluator {
	return &evaluator{
		storage: storage,
	}
}

func (e *evaluator) Evaluate(req Request) (Response, error) {
	statements, err := e.storage.ListStatementsByPrincipal(req.Principal)
	if err != nil {
		return Response{}, fmt.Errorf("failed to list statements: %w", err)
	}

	if len(statements) == 0 {
		return Response{
			Effect:  EffectDeny,
			Message: "no applicable statements found, access denied by default",
		}, nil
	}

	// Separate statements by effect for clear processing order.
	denyStatements := filterStatementsByEffect(statements, EffectDeny)
	allowStatements := filterStatementsByEffect(statements, EffectAllow)

	// Deny statements have the highest precedence. If any deny statement
	// matches, we deny the request immediately.
	for _, stmt := range denyStatements {
		matches, err := statementMatches(stmt, req)
		if err != nil {
			// It's safer to deny if a condition evaluation fails.
			return Response{
				Effect:  EffectDeny,
				Message: fmt.Sprintf("failed to evaluate condition for deny statement %q: %s", stmt.ID, err),
				Decider: &stmt.ID,
			}, nil
		}
		if matches {
			return Response{
				Effect:  EffectDeny,
				Message: fmt.Sprintf("denied by statement %q", stmt.ID),
				Decider: &stmt.ID,
			}, nil
		}
	}

	// If no deny statements matched, we check for allow statements.
	// A single matching allow statement is sufficient to grant access.
	for _, stmt := range allowStatements {
		matches, err := statementMatches(stmt, req)
		if err != nil {
			// Log the error but don't deny, as other allow statements might still match.
			// A failed condition in an allow statement is treated as a non-match.
			fmt.Printf("skipping allow statement %q due to condition error: %s\n", stmt.ID, err)
			continue
		}
		if matches {
			return Response{
				Effect:  EffectAllow,
				Message: fmt.Sprintf("allowed by statement %q", stmt.ID),
				Decider: &stmt.ID,
			}, nil
		}
	}

	// By default, if no statements explicitly allow or deny, we deny access.
	return Response{
		Effect:  EffectDeny,
		Message: "no matching statement found, access denied by default",
	}, nil
}

func enhancePattern(pattern string) string {
	if pattern == "*" {
		return "**" // Treat "*" as a wildcard for any resource
	}
	return pattern	
}

// statementMatches checks if a statement's principals, actions, resources, and conditions
// are all satisfied by the request.
func statementMatches(stmt Statement, req Request) (bool, error) {
	if !principalMatches(stmt.Principals, req.Principal) {
		return false, nil
	}

	if !actionMatches(stmt.Actions, req.Action) {
		return false, nil
	}

	if !resourceMatches(stmt.Resources, req.Resource) {
		return false, nil
	}

	conditionsMet, err := allConditionsMet(stmt.Conditions, req)
	if err != nil {
		return false, err
	}

	return conditionsMet, nil
}

// actionMatches checks if the request's action matches any pattern in the statement's action list.
func actionMatches(actions []ActionID, requestedAction ActionID) bool {
	for _, a := range actions {
		if matched, _ := doublestar.Match(enhancePattern(string(a)), string(requestedAction)); matched {
			return true
		}
	}
	return false
}

// resourceMatches checks if the request's resource matches any pattern in the statement's resource list.
func resourceMatches(resources []Resource, requestedResource Resource) bool {
	for _, r := range resources {
		if matched, _ := doublestar.Match(enhancePattern(string(r)), string(requestedResource)); matched {
			return true
		}
	}
	return false
}

// Add this new function for principal matching
func principalMatches(principals []Principal, requestedPrincipal Principal) bool {
	for _, p := range principals {
		if matched, _ := doublestar.Match(enhancePattern(string(p)), string(requestedPrincipal)); matched {
			return true
		}
	}
	return false
}

// allConditionsMet evaluates all conditions in a statement against the request.
// It returns true only if all conditions pass.
func allConditionsMet(conditions []Condition, req Request) (bool, error) {
	for _, c := range conditions {
		met, err := c.Evaluate(req)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition %q: %w", c.Name, err)
		}
		if !met {
			return false, nil
		}
	}
	return true, nil
}

// filterStatementsByEffect is a utility to get statements of a specific effect.
func filterStatementsByEffect(statements []Statement, effect Effect) []Statement {
	var filtered []Statement
	for _, s := range statements {
		if s.Effect == effect {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
