package authorization

type Response struct {
	Effect  Effect  `json:"effect"`
	Message string  `json:"message"`
	Decider *string `json:"decider,omitempty"`
}

func (r Response) Allowed() bool {
	return r.Effect == EffectAllow
}

func (r Response) Denied() bool {
	return r.Effect == EffectDeny
}

func (r Response) String() string {
	return "Response{" +
		"Effect: " + string(r.Effect) +
		", Message: '" + r.Message + "'" +
		", Decider: " + func() string {
			if r.Decider != nil {
				return *r.Decider
			}
			return "nil"
		}() +
		"}"
}
