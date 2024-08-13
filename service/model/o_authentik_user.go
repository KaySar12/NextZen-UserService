package model

type AuthentikUser struct {
	User struct {
		Avatar string `json:"avatar"`
		Email  string `json:"email"`
		Groups []struct {
			Name string `json:"name"`
			Pk   string `json:"pk"`
		} `json:"groups"`
		IsActive    bool   `json:"is_active"`
		IsSuperuser bool   `json:"is_superuser"`
		Name        string `json:"name"`
		Pk          int64  `json:"pk"`
		Settings    struct {
			Theme struct {
				Base string `json:"base"`
			} `json:"theme"`
		} `json:"settings"`
		SystemPermissions []string `json:"system_permissions"`
		Type              string   `json:"type"`
		UID               string   `json:"uid"`
		Username          string   `json:"username"`
	} `json:"user"`
}
