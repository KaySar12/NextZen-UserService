package model

type CommonModel struct {
	RuntimePath string
}

type APPModel struct {
	LogPath         string
	LogSaveName     string
	LogFileExt      string
	UserDataPath    string
	DBPath          string
	OMVServer       string
	AuthentikServer string
	SecretKey       string
}

type Result struct {
	Success int         `json:"success" example:"200"`
	Message string      `json:"message" example:"ok"`
	Data    interface{} `json:"data" example:"Return result"`
}
