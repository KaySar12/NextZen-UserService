package model

type CommonModel struct {
	RuntimePath string
}

type APPModel struct {
	LogPath      string
	LogSaveName  string
	LogFileExt   string
	UserDataPath string
	DBPath       string
}

type OIDCModel struct {
	AuthServer   string
	ClientID     string
	ClientSecret string
	AuthURL      string
	CallbackURL  string
}

type NextWebModel struct {
	Server       string
	UserName     string
	Password     string
	EntranceCode string
}
type Result struct {
	Success int         `json:"success" example:"200"`
	Message string      `json:"message" example:"ok"`
	Data    interface{} `json:"data" example:"Return result"`
}
