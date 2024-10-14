package utils

import (
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
)

// Location 表示地理位置信息。
type Location struct {
	IPAddress string
	City      string
	Country   string
	Latitude  float64
	Longitude float64
}

// IPDatabase 包含 GeoIP2 数据库路径。
type IPDatabase struct {
	DBPath string
}

// NewIPDatabase 创建一个具有指定数据库路径的新 IPDatabase。
func NewIPDatabase(dbPath string) *IPDatabase {
	return &IPDatabase{
		DBPath: dbPath,
	}
}

// IPToLocation 获取给定 IP 地址的地理位置信息。
func (db *IPDatabase) IPToLocation(ipAddress string) (Location, error) {
	geoDB, err := geoip2.Open(db.DBPath)
	if err != nil {
		return Location{}, err
	}
	defer geoDB.Close()

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return Location{}, errors.New("无效的 IP 地址")
	}

	record, err := geoDB.City(ip)
	if err != nil {
		return Location{}, err
	}

	var city string
	if name, ok := record.City.Names["zh-CN"]; ok {
		city = name
	} else {
		city = record.City.Names["en"]
	}

	var country string
	if name, ok := record.Country.Names["zh-CN"]; ok {
		country = name
	} else {
		country = record.Country.Names["en"]
	}

	location := Location{
		IPAddress: ipAddress,
		City:      city,
		Country:   country,
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
	}

	return location, nil
}

func Geo(ip string) string {
	dbPath := "./GeoLite2-City.mmdb"
	ipDB := NewIPDatabase(dbPath)
	location, err := ipDB.IPToLocation(ip)
	if err != nil {
		log.Printf("IP解析错误：%v", err)
		WriteError(fmt.Sprintf("IP解析错误：%v", err))
	}
	geo := location.Country + location.City
	return geo
}
