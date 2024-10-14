package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 从数据库获取数据

func getLogbasicAnddetail(ID int) (basic *LogBasic, detail *LogDetail, err error) {
	logBasic, err := queryLatestLog(ID)
	if err != nil {
		return nil, nil, err
	}
	logDetail, err := getLogDetail(ID)
	if err != nil {
		return nil, nil, err
	}
	return logBasic, logDetail, nil
}

// 构造告警消息，准备推送

func WarnMessages(ID int, config *Config) {
	logBasic, logDetail, err := getLogbasicAnddetail(ID)
	if err != nil {
		fmt.Printf("Error getting log detail: %v", err)
		WriteError(fmt.Sprintf("Error getting log detail: %v", err))
	}
	// 格式化时间
	formattedTime := time.Now().Format("2006-01-02 15:04:05")
	formattedTimestamp := time.Unix(logBasic.Timestamp, 0).Format("2006-01-02 15:04:05")
	// 解析IP的地理位置
	city := Geo(logBasic.SrcIP)
	// 处理 req_header 和 req_body
	formattedHeader := strings.ReplaceAll(logDetail.ReqHeader, "\n", " ") // 替换换行符为空格
	formattedHeader = strings.ReplaceAll(formattedHeader, "`", "\\`")     // 替换反引号以防止 Markdown 格式问题

	formattedBody := strings.ReplaceAll(logDetail.ReqBody, "\n", " ") // 替换换行符为空格
	formattedBody = strings.ReplaceAll(formattedBody, "`", "\\`")     // 替换反引号以防止 Markdown 格式问题

	// 处理漏洞规则
	RuleStr := VulSub(logBasic.RuleID)
	if RuleStr == "" {
		RuleStr = logBasic.RuleID
	}
	// 构建消息字符串
	message := fmt.Sprintf(
		"**入侵检测事件**\n\n- **告警通知时间:**\n  %s\n- **日志告警时间:**\n  %s\n\n- **受影响设备地址:**\n\n  %s\n- **攻击源地址:**\n\n  %s\n- **攻击来源:**\n\n  %s\n- **触发规则:**\n\n  %s\n- **被攻击路径:**\n\n  %s\n- **完整攻击日志:**\n\n  ```\n%s\n```",
		formattedTime,                        // 告警通知时间
		formattedTimestamp,                   // 日志告警时间
		logBasic.Host,                        // 受影响的设备地址
		city,                                 // 攻击来源地址
		logBasic.SrcIP,                       // 攻击来源IP
		RuleStr,                              // 规则ID
		logBasic.URLPath,                     // 被攻击路径
		formattedHeader+"\r\n"+formattedBody, // 原始攻击日志
	)
	data := DingTalkMessage{
		MsgType: "markdown",
		Markdown: struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		}{
			Title: "入侵检测事件",
			Text:  message,
		},
	}
	switch config.Method {
	case "dingtalk":
		sendDingTalkMessage(config.Token, data)
	case "serverchan":
		sendServerChatMessage(config.Token, data)
	default:
		log.Fatalf("未知的推送方法: %s", config.Method)
	}
}

// 构造拦截事件消息，准备推送

func AclMessage(ID int, config *Config) {
	event, err := queryAclIPEvent(ID)
	if err != nil {
		fmt.Printf("Error getting acl blocked ip: %v", err)
		WriteError(fmt.Sprintf("Error getting acl blocked ip: %v", err))
	}
	// 解析地理位置
	eventGeo := Geo(event.IP)
	message := fmt.Sprintf(
		"**IP拦截处理**\n\n- **告警通知时间:**\n  %s\n- **拦截触发时间:**\n  %v\n\n- **拦截结束时间:**\n\n  %v\n- **攻击源地址:**\n\n  %s\n- **拦截IP源:**\n\n  %s\n- **触发规则:**\n\n  %s\n- **触发拦截次数:**\n\n  %v\n- **拦截结果:**\n\n  %s",
		time.Now().Format("2006-01-02 15:04:05"),
		event.CreatedAt,
		event.ValidBefore,
		eventGeo,
		event.IP,
		event.Reason,
		event.DeniedCount,
		event.Result,
	)
	data := DingTalkMessage{
		MsgType: "markdown",
		Markdown: struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		}{
			Title: "入侵检测事件",
			Text:  message,
		},
	}
	switch config.Method {
	case "dingtalk":
		sendDingTalkMessage(config.Token, data)
	case "serverchan":
		sendServerChatMessage(config.Token, data)
	default:
		log.Fatalf("未知的推送方法: %s", config.Method)
	}
}

// 钉钉推送
func sendDingTalkMessage(token string, message DingTalkMessage) {
	data, err := json.Marshal(message) // 将消息结构体转换为JSON
	if err != nil {
		log.Printf("Error sending DingTalk message: %v", err)
		WriteError(fmt.Sprintf("Error sending DingTalk message: %v", err))
		return
	}
	webhookURL := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", token) // 构建Webhook URL
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(data))            // 发送HTTP POST请求
	if err != nil {
		log.Printf("Error sending DingTalk message: %v", err)
		WriteError(fmt.Sprintf("Error sending DingTalk message: %v", err))
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error sending DingTalk message: %v", resp.Status)              // 打印错误状态码
		WriteError(fmt.Sprintf("Error sending DingTalk message: %v", resp.Status)) // 写入错误日志
	}
}

// Server酱推送
func sendServerChatMessage(token string, message DingTalkMessage) {
	data := url.Values{}
	data.Add("title", message.Markdown.Title)
	data.Add("text", message.Markdown.Text)
	webhookURL := fmt.Sprintf("https://sctapi.ftqq.com/%s.send", token) // 构建Webhook URL
	resp, err := http.PostForm(webhookURL, data)                        // 发送HTTP POST请求
	if err != nil {
		log.Printf("Error sending ServerChat message: %v", err)
		WriteError(fmt.Sprintf("Error sending ServerChat message: %v", resp.Status))
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error sending ServerChat message: %v", resp.Status)
		WriteError(fmt.Sprintf("Error sending ServerChat message: %v", resp.Status))
	}
}
