package authorization

import (
	"os"
	"testing"

	"github.com/joho/godotenv"
)

var (
	ENDPOINT string
	TOKEN    string
)

func init() {
	godotenv.Load()
	ENDPOINT = os.Getenv("REMOTE_ENDPOINT")
	TOKEN    = os.Getenv("REMOTE_BEARER_TOKEN")
}

func TestRemoteAuthorizer(t *testing.T) {
	// Dummy bearer token function
	bearerTokenFn := func() (string, error) {
		return TOKEN, nil
	}

	authorizer := NewBetandbeatRemoteAuthorizer(ENDPOINT, bearerTokenFn)

	req := Request{
		Principal: "users/betandbeat",
		Action:    "iam:DeleteUsers",
		Resource:  "users/johndoe",
		Context:   Context{},
	}

	resp, err := authorizer.Authorize(t.Context(), req)
	if err != nil {
		t.Logf("expected error, got: %v", err)
	}
	if resp.Effect != EffectDeny {
		t.Errorf("expected EffectDeny, got: %v", resp.Effect)
	}
	t.Logf("response: %+v", resp)
}