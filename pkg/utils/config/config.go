package config

import (
	"fmt"

	"github.com/KaySar12/NextZen-UserService/pkg/config"
	"gopkg.in/ini.v1"
)

var (
	Cfg *ini.File
)

func init() {
	var err error
	Cfg, err = ini.Load(config.UserServiceConfigFilePath)
	if err != nil {
		panic(err)
	}
}
func WriteMapToConfig(configData map[string]string, section string) {
	sectionData := Cfg.Section(section)
	for key, value := range sectionData.KeysHash() {
		if value != configData[key] {
			sectionData.Key(key).SetValue(configData[key])
		}
	}
	err := Cfg.SaveTo(config.UserServiceConfigFilePath)
	if err != nil {
		fmt.Println("Failed to save file:", err)
		return
	}

}
