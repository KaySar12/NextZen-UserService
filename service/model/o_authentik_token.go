package model

type AuthentikToken struct {
	Acr               string   `json:"acr"`
	Active            bool     `json:"active"`
	Aud               string   `json:"aud"`
	AuthTime          int64    `json:"auth_time"`
	ClientID          string   `json:"client_id"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Exp               int64    `json:"exp"`
	GivenName         string   `json:"given_name"`
	Groups            []string `json:"groups"`
	Iat               int64    `json:"iat"`
	Iss               string   `json:"iss"`
	Name              string   `json:"name"`
	Nickname          string   `json:"nickname"`
	PreferredUsername string   `json:"preferred_username"`
	Scope             string   `json:"scope"`
	Sub               string   `json:"sub"`
}
