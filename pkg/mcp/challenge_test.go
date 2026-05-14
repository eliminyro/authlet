package mcp

import "testing"

func TestChallengeHeader(t *testing.T) {
	got := ChallengeHeader("https://rs/.well-known/oauth-protected-resource/api")
	want := `Bearer realm="authlet", resource_metadata="https://rs/.well-known/oauth-protected-resource/api"`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
