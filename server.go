package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// AuthResponse is a struct for HTTP responses
type AuthResponse struct {
	Message string `json:"message"`
}

type Config struct {
	AudienceId        string `json:"audience"`
	Issuer            string `json:"issuer"`
	JwksURL           string `json:"jwksUrl"`
	AuthHeaderName    string `json:"authHeaderName"`
	BasicAuthUsername string `json:"basicAuthUsername"`
	BasicAuthPassword string `json:"basicAuthPassword"`
}

var config Config

func main() {
	config = readConfig("appsettings.json")
	http.HandleFunc("/", authHandler)
	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// Check for authentication header
	if r.Header.Get(config.AuthHeaderName) != "" {
		if validateJWT(r) {
			respond(w, http.StatusOK, "Authorization successful")
			log.Println("JWT authorization successful")
			return
		}
	} else if validateBasicAuth(r) {
		respond(w, http.StatusOK, "Authorization successful")
		log.Println("Basic authorization successful")
		return
	}

	// If neither authentication succeeded
	log.Println("Authorization failed")
	respond(w, http.StatusUnauthorized, "Not authorized")
}

func validateJWT(r *http.Request) bool {
	// Extract Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Load JWKS: in real app do it once and cache it in the config
	jwks, err := keyfunc.Get(config.JwksURL, keyfunc.Options{})
	if err != nil {
		log.Printf("Error loading JWKS: %v", err)
		return false
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		log.Printf("JWT validation error: %v", err)
		return false
	}

	// Check token claims.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Failed to parse claims.")
		return false
	}

	// Check the issuer.
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != config.Issuer {
		log.Printf("The token does not have the correct issuer.")
		return false
	}

	// Check the audience id.
	audience, ok := claims["aud"].(string)
	if !ok || audience != config.AudienceId {
		log.Printf("The token does not have the correct audience.")
		return false
	}

	return token.Valid
}

func validateBasicAuth(r *http.Request) bool {
	// Extract basic authentication credentials
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return username == config.BasicAuthUsername && password == config.BasicAuthPassword
}

func respond(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	response := AuthResponse{Message: message}
	json.NewEncoder(w).Encode(response)
}

func readConfig(filePath string) Config {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Fatalf("appsettings.json does not exist.")
	}
	var config Config
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open appsettings.json.\nError: %s", err.Error())
	} else {
		defer file.Close()
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&config); err != nil {
			log.Fatalf("Failed to decode appsettings.json.\nError: %s", err.Error())
		}
	}
	return config
}
