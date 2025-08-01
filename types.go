package authorization

import (
	"time"

	"github.com/expr-lang/expr"
)

type Statement struct {
	ID          string      `json:"id"`
	Active      bool        `json:"active"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Effect      Effect      `json:"effect"`
	Principals  []Principal `json:"principals"`
	Actions     []ActionID  `json:"actions"`
	Resources   []Resource  `json:"resources"`
	Conditions  []Condition `json:"conditions,omitempty"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	CreatedBy   string      `json:"createdBy"`
	UpdatedBy   string      `json:"updatedBy"`
}

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Principal string

type ActionID string

func NewAction(id ActionID, name, description string) Action {
	if id == "" {
		panic("action ID cannot be empty")
	}
	if name == "" {
		name = string(id) // Use ID as name if not provided
	}
	return Action{
		ID:          id,
		Name:        name,
		Description: description,
	}
}

type Action struct {
	ID          ActionID `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
}

func (a Action) String() string {
	return string(a.ID)
}

type Resource string

type Condition struct {
	Name       string
	Expression string
}

type Context struct {
	Request struct {
		At        time.Time `json:"at"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
	}
}

type Response struct {
	Effect  Effect  `json:"effect"`
	Message string  `json:"message"`
	Decider *string `json:"decider,omitempty"`
}

type Storage interface {
	ListStatementsByPrincipal(principal Principal) ([]Statement, error)
}

func (c *Condition) Evaluate(req Request) (bool, error) {
	program, err := expr.Compile(c.Expression)
	if err != nil {
		return false, err
	}
	res, err := expr.Run(program, req)
	if err != nil {
		return false, err
	}
	if result, ok := res.(bool); ok {
		return result, nil
	}
	return false, nil
}
