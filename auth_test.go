package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TODO expand this with table driven tests to cover the last third of statements

var (
	defaultLength = 32
)

func TestNewSecret(t *testing.T) {
	secret, err := NewSecret(defaultLength)
	require.NoError(t, err)
	require.EqualValues(t, defaultLength, len(secret))
	t.Logf("new secret (len:%d): %v\n", len(secret), secret)
}

func TestTokenLifecycle(t *testing.T) {
	// create
	userID := 666
	secret, err := NewSecret(defaultLength)
	require.NoError(t, err)
	token := NewToken(userID, secret)
	t.Logf("token created: %v\n", token)

	// read & format
	parsed, err := ParseToken(token)
	require.NoError(t, err)
	require.EqualValues(t, userID, parsed.Id)
	require.EqualValues(t, secret, parsed.Secret)
	t.Logf("token parsed:  %v\n", parsed.Format())

	// hash and compare
	hashed, err := Hash(parsed.Format(), bcrypt.DefaultCost)
	require.NoError(t, err)
	t.Logf("hashed token: %v\n", hashed)
	cost, err := Cost(hashed)
	require.NoError(t, err)
	require.EqualValues(t, bcrypt.DefaultCost, cost)

	// should match
	match, err := Compare(hashed, parsed.Format())
	require.NoError(t, err)
	require.True(t, match)

	// should not match
	userIdBad := 1312
	secretBad, err := NewSecret(defaultLength)
	require.NoError(t, err)
	tokenBad := NewToken(userIdBad, secretBad)
	hashedBad, err := Hash(tokenBad, bcrypt.DefaultCost)
	require.NoError(t, err)
	// compare bad hash to good token
	matchBad, err := Compare(hashedBad, token)
	require.NoError(t, err)
	require.False(t, matchBad)
}
