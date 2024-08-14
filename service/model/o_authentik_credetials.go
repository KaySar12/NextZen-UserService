package model

import "time"

// Soon to be removed
type AuthentikCredentialsDBModel struct {
	Id           int       `gorm:"column:id;primary_key" json:"id"`
	ClientID     string    `json:"clientId"`
	ClientSecret string    `json:"clientSecret"`
	Server       string    `json:"server"`
	CreatedAt    time.Time `gorm:"<-:create;autoCreateTime" json:"created_at,omitempty"`
	UpdatedAt    time.Time `gorm:"<-:create;<-:update;autoUpdateTime" json:"updated_at,omitempty"`
}

func (p *AuthentikCredentialsDBModel) TableName() string {
	return "o_authentik_credentials"
}
