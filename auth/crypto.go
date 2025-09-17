package auth

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	// BCryptCost defines the computational cost for bcrypt hashing
	// Cost 12 provides good security/performance balance for 2024
	BCryptCost = 12
)

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), BCryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword checks if the provided password matches the hash
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}