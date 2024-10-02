package model

import "time"

// TODO  Refreshtoken
type AuthentikCredentialsDBModel struct {
	Id           int       `gorm:"column:id;primary_key" json:"id"`
	ClientID     string    `json:"clientId"`
	ClientSecret string    `json:"clientSecret"`
	Issuer       string    `json:"issuer"`
	AuthUrl      string    `json:"authUrl"`
	CallbackUrl  string    `json:"callbackUrl"`
	CreatedAt    time.Time `gorm:"<-:create;autoCreateTime" json:"created_at,omitempty"`
	UpdatedAt    time.Time `gorm:"<-:create;<-:update;autoUpdateTime" json:"updated_at,omitempty"`
}

func (p *AuthentikCredentialsDBModel) TableName() string {
	return "o_authentik_credentials"
}
