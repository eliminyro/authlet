package idp

import (
	"context"
	"errors"
	"testing"
)

func TestUserResolverFunc(t *testing.T) {
	r := UserResolverFunc(func(_ context.Context, c Claims) (string, error) {
		if c.Email == "" {
			return "", ErrNoUser
		}
		return "u-" + c.Email, nil
	})
	id, err := r.Resolve(context.Background(), Claims{Email: "a@b"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "u-a@b" {
		t.Fatalf("got %q", id)
	}
	if _, err := r.Resolve(context.Background(), Claims{}); !errors.Is(err, ErrNoUser) {
		t.Fatalf("got %v", err)
	}
}
