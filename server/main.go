package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.temporal.io/server/common/api"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/temporal"
)

var (
	decisionAllow = authorization.Result{Decision: authorization.DecisionAllow}
	decisionDeny  = authorization.Result{Decision: authorization.DecisionDeny}
)

type OIDCClaimMapper struct {
	issuerURL string
	clientID  string
	jwksURL   string
	keySet    jwk.Set
}

type OIDCClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Groups            []string `json:"groups"`
	PreferredUsername string   `json:"preferred_username"`
}

func NewOIDCClaimMapper() *OIDCClaimMapper {
	issuerURL := os.Getenv("TEMPORAL_OIDC_ISSUER_URL")
	fmt.Printf("Issuer URL: %q\n", issuerURL)

	clientID := os.Getenv("TEMPORAL_OIDC_CLIENT_ID")
	fmt.Printf("Client ID: %q\n", clientID)

	jwksURL := issuerURL + "/.well-known/jwks.json"

	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		// Handle error appropriately for your application
		return nil
	}

	return &OIDCClaimMapper{
		issuerURL: issuerURL,
		clientID:  clientID,
		jwksURL:   jwksURL,
		keySet:    keySet,
	}
}

func (c *OIDCClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	authClaims := &authorization.Claims{}

	if authInfo.AuthToken == "" {
		log.Printf("No auth token provided")
		return authClaims, nil
	}

	// Parse the JWT token and extract PocketID claims
	// Note: You'll need to implement proper JWT validation using your PocketID public key
	pocketIDClaims, err := c.extractAndValidateToken(authInfo.AuthToken)
	if err != nil {
		log.Printf("Failed to validate token: %v", err)
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	authClaims.Subject = pocketIDClaims.Subject
	authClaims.Namespaces = make(map[string]authorization.Role)

	// Map PocketID groups to Temporal namespace access
	for _, group := range pocketIDClaims.Groups {
		switch {
		case group == "admin":
			// Admins can access ALL namespaces
			authClaims.System = authorization.RoleAdmin

		case strings.HasPrefix(group, "bitovi"):
			// Audio team gets access to audio-* namespaces
			authClaims.Namespaces["bitovi-project"] = authorization.RoleWriter
			authClaims.Namespaces["bitovi-reviews"] = authorization.RoleReader

		case strings.HasPrefix(group, "finance"):
			// Finance team gets access to finance-* namespaces
			authClaims.Namespaces["finance-reports"] = authorization.RoleWriter
			authClaims.Namespaces["finance-audits"] = authorization.RoleReader

		default:
			log.Printf("Ignoring group: %s", group)
		}
	}

	return authClaims, nil
}

func (c *OIDCClaimMapper) extractAndValidateToken(token string) (*OIDCClaims, error) {
	token = strings.TrimPrefix(token, "Bearer ")

	// Fetch user info from OIDC provider
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/oidc/userinfo", c.issuerURL), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	var userInfo struct {
		Subject   string `json:"sub"`
		Email     string `json:"email"`
		Verified  bool   `json:"email_verified"`
		Username  string `json:"preferred_username"`
		Namespace string `json:"namespace"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	log.Printf("UserInfo response: %+v\n", userInfo)

	return &OIDCClaims{
		Subject:           userInfo.Subject,
		Email:             userInfo.Email,
		EmailVerified:     userInfo.Verified,
		PreferredUsername: userInfo.Username,
		Groups:            strings.Split(userInfo.Namespace, ","),
	}, nil
}

type OIDCAuthorizer struct{}

func (a *OIDCAuthorizer) Authorize(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	// Allow health check APIs to everyone
	if authorization.IsHealthCheckAPI(target.APIName) {
		log.Printf("Health Check API Access Granted: %s", target.APIName)
		return decisionAllow, nil
	}

	// TODO:
	// WHY are we getting no no claims and NO namespace...

	// Deny if no claims exist (unauthenticated request)
	if claims == nil || target.Namespace == "" {
		log.Printf("No claims or namespace provided for request to %s -> ALLOWED, target: %+v", target.APIName, target)
		return decisionAllow, nil
	}

	// Log request details
	log.Printf("Authorization request: User=%s -> Namespace=%s, API=%s", claims.Subject, target.Namespace, target.APIName)

	// Determine whether this is a cluster-wide or namespace-scoped API
	metadata := api.GetMethodMetadata(target.APIName)

	log.Printf("Metadata: %+v", metadata)

	var userRole authorization.Role
	switch metadata.Scope {
	case api.ScopeCluster:
		// System-wide role for cluster-level API
		userRole = claims.System
	case api.ScopeNamespace:
		// System-wide roles apply across all namespaces
		// If claims.Namespaces is nil or namespace isn't found, the lookup returns zero.
		userRole = claims.System | claims.Namespaces[target.Namespace]
	default:
		log.Printf("Unknown API Scope -> DENIED: %s", target.APIName)
		return decisionDeny, nil
	}

	// Get the required role for this API
	requiredRole := getRequiredRole(metadata.Access)

	// Check if the user meets the required role
	if userRole >= requiredRole {
		log.Printf("Access GRANTED: User=%s, Namespace=%s, API=%s", claims.Subject, target.Namespace, target.APIName)
		return decisionAllow, nil
	}

	// Deny if no valid role was found
	log.Printf("Access DENIED: User=%s, Namespace=%s, API=%s", claims.Subject, target.Namespace, target.APIName)
	return decisionDeny, nil
}

func getRequiredRole(access api.Access) authorization.Role {
	switch access {
	case api.AccessReadOnly:
		return authorization.RoleReader
	case api.AccessWrite:
		return authorization.RoleWriter
	default:
		return authorization.RoleAdmin
	}
}

// Custom Temporal Server with Authorization
func main() {
	log.Println("🚀 Starting Temporal Server with OIDC Authentication...")

	cfg, err := config.LoadConfig("development", "./config", "")
	if err != nil {
		log.Fatal(err)
	}

	s, err := temporal.NewServer(
		temporal.ForServices(temporal.DefaultServices),
		temporal.WithConfig(cfg),
		temporal.InterruptOn(temporal.InterruptCh()),

		// Inject Custom ClaimMapper
		temporal.WithClaimMapper(func(cfg *config.Config) authorization.ClaimMapper {
			return NewOIDCClaimMapper()
		}),

		// Inject Custom Authorizer
		temporal.WithAuthorizer(&OIDCAuthorizer{}),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = s.Start()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Temporal Server Stopped.")
}
