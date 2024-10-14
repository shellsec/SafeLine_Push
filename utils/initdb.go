package utils

import (
	"bufio"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
	"strings"
	"time"
)

var db *gorm.DB

// 读取 .pgpass 文件并返回数据库连接字符串
func readPgPass(filePath, dbname string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			continue
		}
		host, port, db, user, password := parts[0], parts[1], parts[2], parts[3], parts[4]
		if db == dbname {
			dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable TimeZone=Asia/Shanghai",
				host, port, user, db, password)
			return dsn, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("no matching entry found in .pgpass file")
}

// init函数在程序启动时自动调用，连接数据库
func init() {
	// 指定 .pgpass 文件路径和数据库名称
	pgpassPath := "/var/scripts/.pgpass"
	dbname := "safeline-ce"

	// 读取 .pgpass 文件并生成连接字符串
	dsn, err := readPgPass(pgpassPath, dbname)
	if err != nil {
		log.Fatalf("Failed to read .pgpass file: %v", err)
	}

	// 连接数据库
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// 测试数据库连接是否正常
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get database: %v", err)
	}

	// 设置连接池参数（可选）
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	log.Println("Database connected successfully.")
}

// 查询因频繁访问或频繁工具封禁的IP事件
func queryAclIPEvent(aclId int) (*AclBlockedIp, error) {
	var acl AclBlockedIp
	err := db.Table("mgt_acl_blocked_ip").
		Where("id>?", aclId).
		Order("id ASC").
		Limit(1).
		Scan(&acl).Error
	if err != nil {
		return nil, err
	}
	if acl.ID == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &acl, nil
}

// 查询最新的basic表中WAF攻击事件日志

func queryLatestLog(lastID int) (*LogBasic, error) {
	var logbasic LogBasic
	err := db.Table("mgt_detect_log_basic").
		Where("id>?", lastID).
		Order("id ASC").
		Limit(1).
		Scan(&logbasic).Error
	if err != nil {
		return nil, err
	}
	if logbasic.ID == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &logbasic, nil
}

// 获取 req_header 和 req_body
func getLogDetail(lastID int) (*LogDetail, error) {
	var detail LogDetail
	err := db.Table("mgt_detect_log_detail").
		Where("id = ?", lastID).
		Order("id ASC").
		Limit(1).
		Scan(&detail).Error
	if err != nil {
		return nil, err
	}
	return &detail, nil
}

// 获取basic最后一条WAF攻击事件日志的ID
func getLastId() (int, error) {
	var lastID int
	err := db.Table("mgt_detect_log_basic").
		Order("id DESC").
		Limit(1).
		Pluck("id", &lastID).Error
	if err != nil {
		return 0, err
	}
	return lastID, nil
}

// 获取acl频率、攻击拦截ID

func GetAclId() (int, error) {
	var aclID int
	err := db.Table("mgt_acl_blocked_ip").
		Order("id DESC").
		Limit(1).
		Pluck("id", &aclID).Error
	if err != nil {
		return 0, err
	}
	return aclID, nil
}

// 循环查询最新的攻击日志

func getLog(config *Config) {
	lastID, err := getLastId()
	if err != nil {
		log.Printf("Failed to get last id: %v", err)
		WriteError(fmt.Sprintf("Failed to get last id: %v", err))
	}
	aclId, err := GetAclId()
	if err != nil {
		log.Printf("Failed to get acl ID id: %v", err)
		WriteError(fmt.Sprintf("Failed to get acl ID id: %v", err))
	}
	eventMessage := false
	noNewLogMessage := false                  // 标志变量
	ticker := time.NewTicker(1 * time.Second) // 每秒检查一次
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 尝试获取新日志条目
			logEntry, err := queryLatestLog(lastID)
			if err != nil && err.Error() != "record not found" {
				log.Printf("Error fetching log entry: %v", err)
				continue
			}
			aclEntry, err := queryAclIPEvent(aclId)
			if err != nil && err.Error() != "record not found" {
				log.Printf("Error fetching log entry: %v", err)
				continue
			}
			if logEntry != nil {
				// 处理新日志
				WarnMessages(lastID, config)
				lastID++               // 更新 lastID，假设每次有新日志就增加
				noNewLogMessage = true // 重置标志变量
			} else if noNewLogMessage {
				// 只在没有新日志的情况下输出一次
				log.Println("No new log entries.")
				noNewLogMessage = false // 更新标志变量
			}
			if aclEntry != nil {
				// 处理新的IP拦截事件
				time.Sleep(1 * time.Second) // 延迟1秒等待数据库更新!
				AclMessage(aclId, config)
				aclId++             // 更新 aclID,假设每次都有新的拦截事件
				eventMessage = true // 重置标志变量
			} else if eventMessage {
				// 只在没有新日志的情况下输出一次
				log.Println("No new event entries.")
				eventMessage = false // 更新标志变量
			}
		}
	}
}
