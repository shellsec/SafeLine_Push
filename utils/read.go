package utils

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

func ReadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var Conf Config
	err = yaml.Unmarshal(data, &Conf)
	if err != nil {
		return nil, err
	}
	return &Conf, nil
}

func Exec(name string) {
	conf, err := ReadConfig(name)
	if err != nil {
		log.Printf("Error reading config file: %v", err)
		WriteError(fmt.Sprintf("%s Error reading config file: %v\n", time.Now().Format("2006-01-02 15:04:05"), err))
	}
	getLog(conf)
}

// 加载json文件
func loadConfig() (*VulConfig, error) {
	filename := "/var/scripts/VulConfig.json"
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config VulConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func replaceStrings(input string, replacements map[string]string) string {
	for old, new := range replacements {
		input = strings.ReplaceAll(input, old, new)
	}
	return input
}

func VulSub(str string) string {
	conf, err := loadConfig()
	if err != nil {
		log.Printf("读取漏洞规则文件失败: %v", err)
		WriteError(fmt.Sprintf("%s 读取漏洞规则文件失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err))
		return ""
	}
	newStr := replaceStrings(str, conf.Replacements)
	return newStr
}
