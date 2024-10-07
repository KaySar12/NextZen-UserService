package model

import "time"

type InstalledAppRequest struct {
	Page     int           `json:"page"`
	PageSize int           `json:"pageSize"`
	Name     string        `json:"name"`
	Tags     []interface{} `json:"tags"`
	Update   bool          `json:"update"`
	Sync     bool          `json:"sync"`
}

type InstalledAppResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Items []struct {
			ID            int       `json:"id"`
			Name          string    `json:"name"`
			AppID         int       `json:"appID"`
			AppDetailID   int       `json:"appDetailID"`
			Version       string    `json:"version"`
			Status        string    `json:"status"`
			Message       string    `json:"message"`
			HTTPPort      int       `json:"httpPort"`
			HTTPSPort     int       `json:"httpsPort"`
			Path          string    `json:"path"`
			CanUpdate     bool      `json:"canUpdate"`
			Icon          string    `json:"icon"`
			AppName       string    `json:"appName"`
			Ready         int       `json:"ready"`
			Total         int       `json:"total"`
			AppKey        string    `json:"appKey"`
			AppType       string    `json:"appType"`
			AppStatus     string    `json:"appStatus"`
			DockerCompose string    `json:"dockerCompose"`
			CreatedAt     time.Time `json:"createdAt"`
			App           struct {
				Website  string `json:"website"`
				Document string `json:"document"`
				Github   string `json:"github"`
			} `json:"app"`
		} `json:"items"`
	} `json:"data"`
}
