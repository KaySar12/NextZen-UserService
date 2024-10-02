package model

type OnePanelCredentials struct {
	Name          string `json:"name"`
	Password      string `json:"password"`
	IgnoreCaptcha bool   `json:"ignoreCaptcha"`
	Captcha       string `json:"captcha"`
	CaptchaID     string `json:"captchaID"`
	AuthMethod    string `json:"authMethod"`
	Language      string `json:"language"`
}

type LoginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		MfaStatus string `json:"mfaStatus"`
	} `json:"data"`
}

type LogoutResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
	} `json:"data"`
}
