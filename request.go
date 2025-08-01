package authorization

import "fmt"

type Request struct {
	Principal Principal `json:"principal" expr:"principal"`
	Action    ActionID  `json:"action" expr:"action"`
	Resource  Resource  `json:"resource" expr:"resource"`
	Context   Context   `json:"context" expr:"context"`
}

func (r Request) WithPrincipal(principal string) Request {
	r.Principal = Principal(principal)
	return r
}

func (r Request) WithUserPrincipal(userId string) Request {
	r.Principal = Principal(fmt.Sprintf("users/%s", userId))
	return r
}

func (r Request) WithRolePrincipal(roleId string) Request {
	r.Principal = Principal(fmt.Sprintf("roles/%s", roleId))
	return r
}

func (r Request) WithServicePrincipal(serviceId string) Request {
	r.Principal = Principal(fmt.Sprintf("services/%s", serviceId))
	return r
}

func (r Request) WithAction(action ActionID) Request {
	r.Action = action
	return r
}

func (r Request) WithResource(resource string) Request {
	r.Resource = Resource(resource)
	return r
}

func (r Request) WithContext(context Context) Request {
	r.Context = context
	return r
}

func (r Request) String() string {
	return fmt.Sprintf("Request{Principal: %s, Action: %s, Resource: %s, Context: %+v}", r.Principal, r.Action, r.Resource, r.Context)
}	