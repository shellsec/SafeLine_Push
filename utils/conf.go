package utils

import "time"

// 钉钉消息推送结构体

type DingTalkMessage struct {
	MsgType  string `json:"msgtype"`
	Markdown struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown"`
}

// Config 结构体，用于存储从配置文件读取的配置信息
type Config struct {
	Token  string `yaml:"token"` // DingTalk 机器人access_token
	Method string `yaml:"method"`
	//API    string `yaml:"api"` // 雷池WAF API_KEY
}

// LogBasic 表示 MGT_DETECT_LOG_BASIC 表的模型
type LogBasic struct {
	ID        int    `gorm:"column:id"`
	EventID   string `gorm:"column:event_id"`  // 关联ID
	Timestamp int64  `gorm:"column:timestamp"` // 数据库中时间戳
	SrcIP     string `gorm:"column:src_ip"`
	Host      string `gorm:"column:host"`
	DstPort   int    `gorm:"column:dst_port"`
	URLPath   string `gorm:"column:url_path"`
	RuleID    string `gorm:"column:rule_id"`
}

// LogDetail 表示 MGT_DETECT_LOG_DETAIL 表的模型
type LogDetail struct {
	EventID   string `gorm:"column:event_id"` // 关联ID
	ReqHeader string `gorm:"column:req_header"`
	ReqBody   string `gorm:"column:req_body"`
}

// AclBlockedIp 表示 MGT_ACL_BLOCKED_IP 表的模型
type AclBlockedIp struct {
	ID          int       `gorm:"column:id"`
	CreatedAt   time.Time `gorm:"column:created_at"` // 触发时间
	ValidBefore time.Time `gorm:"valid_before"`      // 封禁结束时间
	IP          string    `gorm:"column:ip"`
	DeniedCount int       `gorm:"column:denied_count"` // 触发拦截次数
	Reason      string    `gorm:"column:reason"`       // 触发拦截原因
	Result      string    `gorm:"column:result"`       // 拦截结果ban/challenge
}

// 漏洞规则结构体

type VulConfig struct {
	Replacements map[string]string `json:"replacements"`
}
