package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type RemoteAuthorizer interface {
	Authorize(ctx context.Context, req Request) (Response, error)
}

type remoteAuthorizer struct {
	client       http.Client
	endpoint   string
	bearerTokenFn func() (string, error)
}

func NewBetandbeatRemoteAuthorizer(endpoint string, bearerTokenFn func() (string, error)) RemoteAuthorizer {
	client := http.Client{
		Timeout: 10 * time.Second, // Set a reasonable timeout for remote requests
	}
	return &remoteAuthorizer{
		client:       client,
		endpoint:      endpoint,
		bearerTokenFn: bearerTokenFn,
	}
}

func (r *remoteAuthorizer) Authorize(ctx context.Context, req Request) (Response, error) {
	token, err := r.bearerTokenFn()
	if err != nil {
		return Response{}, err
	}

	// Prepare the request body
	body, err := json.Marshal(req)
	if err != nil {
		return Response{
			Effect: EffectDeny,
			Message: "failed to marshal authorization request: " + err.Error(),
		}, err
	}
	bodyRead := bytes.NewReader(body)

	// Prepare the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bodyRead)
	if err != nil {
		return Response{
			Effect: EffectDeny,
			Message: "failed to create authorization request: " + err.Error(),
		}, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return Response{
			Effect: EffectDeny,
			Message: "failed to make authorization request: " + err.Error(),
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return Response{
				Effect: EffectDeny,
				Message: "failed to decode error response: " + err.Error(),
			}, fmt.Errorf("authorization failed: %s", resp.Status)
		} else {
			fmt.Println("Error response body:", string(body))
			return Response{
				Effect: EffectDeny,
				Message: fmt.Sprintf("authorization failed with status %s", resp.Status),
			}, fmt.Errorf("authorization failed with status %s", resp.Status)
		}
	}

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{
			Effect: EffectDeny,
			Message: "failed to decode authorization response: " + err.Error(),
		}, err
	}

	return response, nil
}