// package auth wraps bcrypt to provide some basic functionality,
// adding a Token object which combines a distinct user id
// with that users secret to make a token in format <id>:<secret>
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const tokenDelimiter string = ":"

type Token struct {
	Id     int    // correlates with db: users.id
	Secret string // correlates with hashed db: users.hashed_secret
}

// NewSecret creates a new base64 encoded secret
func NewSecret(length int) (string, error) {
	// Calculate the required byte length to achieve the desired base64 length
	byteLength := (length * 3) / 4
	if (length*3)%4 != 0 {
		byteLength++
	}

	password := make([]byte, byteLength)
	_, err := rand.Read(password)
	if err != nil {
		return "", fmt.Errorf("error generating random password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(password), nil
}

// NewToken formats into standard '<id>:<secret>'
func NewToken(userID int, secret string) string {
	return fmt.Sprintf("%d%s%s", userID, tokenDelimiter, secret)
}

// ParseToken takes a token in '<id>:<secret>' format
// and returns a Token struct
func ParseToken(token string) (Token, error) {
	parts := strings.Split(token, tokenDelimiter)
	if len(parts) != 2 {
		return Token{}, fmt.Errorf("token is not in '<id>:<secret>' format")
	}
	if len(parts[0]) == 0 {
		return Token{}, fmt.Errorf("id cannot be empty")
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		return Token{}, fmt.Errorf("id is not valid integer")
	}
	if len(parts[1]) == 0 {
		return Token{}, fmt.Errorf("secret cannot be empty")
	}
	return Token{Id: id, Secret: parts[1]}, nil
}

// Format takes 'id' and 'secret' and formats a string as '<id>:<secret>'
func (t *Token) Format() string {
	return fmt.Sprintf("%d%s%s",
		t.Id,
		tokenDelimiter,
		t.Secret,
	)
}

// Hash uses bcrypt to create a Hash from plaintext password
func Hash(plaintext string, cost int) (string, error) {
	if cost == 0 {
		slog.Warn("provided hash cost too low, increasing to default",
			"provided", cost,
			"default", bcrypt.DefaultCost,
		)
		cost = bcrypt.DefaultCost
	}
	if plaintext == "" {
		return "", fmt.Errorf("no plaintext available to hash")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", fmt.Errorf("unable to generate hash: %w", err)
	}
	return string(hash), nil
}

// Compare compares a provided string to an expected string.
// NOTE: make sure you're comparing *tokens* (<id>:<secret>)
// and not just the secret
func Compare(hash string, plaintext string) (bool, error) {
	if hash == "" {
		return false, fmt.Errorf("no hash provided for comparison")
	}
	if plaintext == "" {
		return false, fmt.Errorf("no plaintext provided for comparison")
	}
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(plaintext),
	)
	return err == nil, nil
}

// Cost calculates the cost of the hash
func Cost(secret string) (int, error) {
	cost, err := bcrypt.Cost([]byte(secret))
	if err != nil {
		return 0, fmt.Errorf("unable to get cost of hash: %w", err)
	}
	return cost, nil
}
