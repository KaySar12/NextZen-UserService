package model

type OMVLogin struct {
	Response struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		Permissions   struct {
			Role string `json:"role"`
		} `json:"permissions"`
		SessionID string `json:"sessionid"`
	} `json:"response"`
	Error interface{} `json:"error"`
}
type OMVUser struct {
	Response struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		Permissions   struct {
			Role string `json:"role"`
		} `json:"permissions"`
	} `json:"response"`
	Error interface{} `json:"error"`
}
