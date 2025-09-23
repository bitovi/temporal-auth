package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	Subject string   `json:"sub"`
	Groups  []string `json:"groups"`
}

func NewOIDCClaimMapper() authorization.ClaimMapper {
	issuerURL := os.Getenv("TEMPORAL_AUTH_PROVIDER_URL")
	clientID := os.Getenv("TEMPORAL_AUTH_CLIENT_ID")

	if issuerURL == "" {
		log.Fatalf("WARNING: TEMPORAL_AUTH_PROVIDER_URL environment variable is not set")
	}

	if clientID == "" {
		log.Fatalf("WARNING: TEMPORAL_AUTH_CLIENT_ID environment variable is not set")
	}

	jwksURL := issuerURL + "/v1/keys"
	log.Printf("Initializing OIDC with issuer: %s, client: %s", issuerURL, clientID)

	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		log.Fatalf("Failed to fetch JWKS from %s: %v", jwksURL, err)
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

	// Parse the JWT token and extract OIDC claims
	claims, err := c.extractAndValidateToken(authInfo.AuthToken)
	if err != nil {
		log.Printf("Failed to validate token: %v", err)
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	authClaims.Subject = claims.Subject
	authClaims.Namespaces = make(map[string]authorization.Role)

	// Map Okta groups to Temporal access
	for _, group := range claims.Groups {
		switch {
		case group == "temporal:system:admin":
			// System admins can access ALL namespaces
			authClaims.System = authorization.RoleAdmin
			log.Printf("User %s granted system admin access", claims.Subject)

		case strings.HasPrefix(group, "temporal:namespace:"):
			// Namespace-specific access: temporal:namespace:namespace-name:role
			parts := strings.Split(group, ":")
			if len(parts) >= 4 {
				namespace := parts[2]
				role := parts[3]

				switch role {
				case "admin":
					authClaims.Namespaces[namespace] = authorization.RoleAdmin
				case "writer":
					authClaims.Namespaces[namespace] = authorization.RoleWriter
				case "reader":
					authClaims.Namespaces[namespace] = authorization.RoleReader
				default:
					log.Printf("Unknown role %s for namespace %s", role, namespace)
				}
				log.Printf("User %s granted %s access to namespace %s", claims.Subject, role, namespace)
			}

		default:
			log.Printf("Ignoring group: %s", group)
		}
	}

	return authClaims, nil
}

func (c *OIDCClaimMapper) extractAndValidateToken(token string) (*OIDCClaims, error) {
	token = strings.TrimPrefix(token, "Bearer ")

	if c.issuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is not configured")
	}

	// Parse and validate the JWT token
	parsedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(c.keySet), jwt.WithValidate(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract claims from the token
	subject, _ := parsedToken.Get("sub")
	groups, _ := parsedToken.Get("groups")

	var groupsList []string
	if groups != nil {
		if groupsSlice, ok := groups.([]interface{}); ok {
			for _, g := range groupsSlice {
				if groupStr, ok := g.(string); ok {
					groupsList = append(groupsList, groupStr)
				}
			}
		}
	}

	subjectStr := ""
	if subject != nil {
		subjectStr = fmt.Sprintf("%v", subject)
	}

	return &OIDCClaims{
		Subject: subjectStr,
		Groups:  groupsList,
	}, nil
}

func NewOIDCAuthorizer() authorization.Authorizer {
	return &OIDCAuthorizer{}
}

type OIDCAuthorizer struct{}

func (a *OIDCAuthorizer) Authorize(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	log.Printf("Authorizing request: %s, claims: %+v, target: %+v", target.APIName, claims, target.Namespace)

	// Allow health check APIs to everyone
	if authorization.IsHealthCheckAPI(target.APIName) {
		log.Printf("Health Check API Access Granted: %s", target.APIName)
		return decisionAllow, nil
	}

	// Allow all operations for system-level admins and writers
	if claims != nil && claims.System&(authorization.RoleAdmin|authorization.RoleWriter) != 0 {
		log.Printf("System admin/writer access granted for user: %s", claims.Subject)
		return decisionAllow, nil
	}

	// For UpdateNamespace API, require writer role in the target namespace
	if strings.Contains(target.APIName, "UpdateNamespace") {
		if claims != nil && claims.Namespaces[target.Namespace]&authorization.RoleWriter != 0 {
			log.Printf("UpdateNamespace access granted for user %s in namespace %s", claims.Subject, target.Namespace)
			return decisionAllow, nil
		}
		log.Printf("UpdateNamespace access denied for user %s in namespace %s", claims.Subject, target.Namespace)
		return decisionDeny, nil
	}

	// For namespace-specific operations, check if user has any access to the namespace
	if target.Namespace != "" && claims != nil {
		userRole := claims.System | claims.Namespaces[target.Namespace]
		if userRole == 0 {
			log.Printf("User %s has no access to namespace %s -> DENIED", claims.Subject, target.Namespace)
			return decisionDeny, nil
		}
	}

	// Allow all other requests
	log.Printf("Access GRANTED: User=%s, Namespace=%s, API=%s", claims.Subject, target.Namespace, target.APIName)
	return decisionAllow, nil
}

// Custom Temporal Server with Authorization
func main() {
	log.Println("🚀 Starting Temporal Server with OIDC Authentication...")

	startService := []string{}

	// Get Target Service
	temporalService := os.Getenv("SERVICES")
	if temporalService != "" {
		log.Printf("Starting service: %s", temporalService)
		if temporalService != "frontend" && temporalService != "matching" && temporalService != "history" && temporalService != "worker" && temporalService != "internal-frontend" {
			log.Fatalf("Invalid SERVICES: %s", temporalService)
		}
		startService = []string{temporalService}

	} else {
		log.Printf("Starting all services")
		startService = temporal.DefaultServices
	}

	configFn := os.Getenv("TEMPORAL_CONFIG_FILENAME")
	if configFn == "" {
		configFn = "development"
	}
	configPath := os.Getenv("TEMPORAL_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config"
	}

	cfg, err := config.LoadConfig(configFn, configPath, "")
	if err != nil {
		log.Fatal(err)
	}

	oidc := NewOIDCClaimMapper()
	claim := NewOIDCAuthorizer()

	if slices.Contains(startService, "internal-frontend") {
		log.Printf("Using noop authentication for internal-frontend")
		oidc = authorization.NewNoopClaimMapper()
		claim = authorization.NewNoopAuthorizer()
	}

	s, err := temporal.NewServer(
		temporal.ForServices(startService),
		temporal.WithConfig(cfg),
		temporal.InterruptOn(temporal.InterruptCh()),

		// Inject Custom ClaimMapper
		temporal.WithClaimMapper(func(cfg *config.Config) authorization.ClaimMapper {
			return oidc
		}),

		// Inject Custom Authorizer
		temporal.WithAuthorizer(claim),
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
