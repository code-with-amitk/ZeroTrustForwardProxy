package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"zerotrust-forward-proxy/utils"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// accessTokenTTL returns JWT access token lifetime from JWT_ACCESS_EXPIRY_HOURS (default 24 hours).
func accessTokenTTL() time.Duration {
	const defaultHours = 24
	s := os.Getenv("JWT_ACCESS_EXPIRY_HOURS")
	if s == "" {
		return time.Duration(defaultHours) * time.Hour
	}
	h, err := strconv.Atoi(s)
	if err != nil || h <= 0 {
		return time.Duration(defaultHours) * time.Hour
	}
	return time.Duration(h) * time.Hour

	// // For testing
	// return 3 * time.Minute
}

// AccessTokenTTLSeconds is the access JWT lifetime in whole seconds (for API responses).
func AccessTokenTTLSeconds() int64 {
	return int64(accessTokenTTL().Seconds())
}

// This function would be called after IDP authentication has authenticated the user
// GenerateJWT issues a short-lived access token (not tied to subscription length).
func GenerateJWT(logger *zap.SugaredLogger, user string, tenantID string) (string, error) {
	if logger != nil {
		logger.Info(utils.GetFunctionName())
	}

	claims := JWTClaim{
		User:     user,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenTTL())),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//secret := os.Getenv("JWT_SECRET")
	secret := "Passw0rd@432"
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	if logger != nil {
		logger.Debug("JWT token for user {", user, "}, token {", tokenString, "}")
	}
	return tokenString, nil
}

// Parse with claims from JWT Token
func ValidateJWT(logger *zap.SugaredLogger, jwttoken string) (*JWTClaim, error) {
	if logger != nil {
		logger.Info(utils.GetFunctionName())
	}

	var err error
	var parsedtoken *jwt.Token
	var claims *JWTClaim

	// Has to be done Global
	//secret := os.Getenv("JWT_SECRET")
	secret := "Passw0rd@432"

	if secret != "" {
		jwttoken = strings.TrimSpace(jwttoken) // Remove leading/trailing whitespace
		jwttoken = strings.Trim(jwttoken, `"`) // Remove surrounding quotes if any

		if jwttoken != "" {
			parsedtoken, err = jwt.ParseWithClaims(jwttoken, &JWTClaim{}, func(token *jwt.Token) (interface{}, error) {
				if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, errors.New("unexpected signing method")
				}
				return []byte(secret), nil
			})

			if err == nil {
				claims = parsedtoken.Claims.(*JWTClaim)
			}
		} else {
			err = fmt.Errorf("jwttoken is null")
		}
	} else {
		err = fmt.Errorf("jwt_secret not set in env")
	}

	return claims, err
}

// Extract JWT token from Authorization header
func IsJWTTokenPresentInHeader(logger *zap.SugaredLogger, r *http.Request) (string, error) {
	logger.Info(utils.GetFunctionName())

	var err error
	var authHdr string
	var tokenParts []string
	var jwttoken string

	authHdr = r.Header.Get("Authorization")
	if authHdr != "" {
		tokenParts = strings.SplitN(strings.TrimSpace(authHdr), " ", 2)
		if len(tokenParts) == 2 && strings.EqualFold(tokenParts[0], "Bearer") && strings.TrimSpace(tokenParts[1]) != "" {
			jwttoken = strings.TrimSpace(tokenParts[1])
		} else {
			err = fmt.Errorf("bearer token not found")
		}
	} else {
		err = fmt.Errorf("authorization header empty in HTTP")
	}

	return jwttoken, err
}

func GetClaimsFromJWT(logger *zap.SugaredLogger, r *http.Request) (*JWTClaim, error) {
	logger.Info(utils.GetFunctionName())

	if c := ClaimsFromRequest(r); c != nil {
		return c, nil
	}

	var claims *JWTClaim
	var jwttoken string
	var err error

	jwttoken, err = IsJWTTokenPresentInHeader(logger, r)
	//logger.Debug does not have inbuilt facility to print jwt format
	logger.Debug("jwtoken", zap.Any("token", jwttoken))
	if err == nil {
		claims, err = ValidateJWT(logger, jwttoken)
	}

	return claims, err
}
