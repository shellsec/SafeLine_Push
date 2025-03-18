```markdown
# SafeLine_Push - 雷池WAF自动化安全运营助手

![雷池WAF](https://zone.huoxian.cn/uploads/202401/1705990046-6583b0be5c4c5.png)

## 📖 项目简介
专为雷池社区版WAF设计的自动化告警推送解决方案，实现：
- 实时攻击告警推送
- 高频IP自动封禁通知
- 完整攻击payload捕获
- 多平台集成（钉钉/飞书等）

## 🚀 核心功能
### 告警推送
- 支持SQL注入/XSS/CSRF等20+攻击类型识别
- 完整请求报文记录（Header+Body）
- 智能规则匹配（`VulConfig.json`自定义规则）

### 频率封禁
- IP访问频率监控
- 自动触发封禁机制
- 可视化封禁记录推送

## 🛠️ 前置准备
### 数据库配置
```bash
# 1. 执行更新脚本
bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/upgrade.sh)"

# 2. 修改compose.yaml（端口映射）
cd /data/safeline
sed -i '/container_name: safeline-pg/a\ ports:\n - 5433:5432' compose.yaml

# 3. 重启服务
docker compose down --remove-orphans && docker compose up -d
```

### 认证配置
```bash
# 获取数据库密码
cat /data/safeline/.env | grep POSTGRES_PASSWORD

# 创建.pgpass文件
echo "localhost:5433:safeline-ce:safeline-ce:your_password" > /var/scripts/.pgpass
chmod 600 /var/scripts/.pgpass
```

## 🔧 安装部署
```bash
# 克隆仓库
git clone https://github.com/Fiary-Tale/SafeLine_Push

# 配置文件放置
cp SafeLine_Push/mark/VulConfig.json /var/scripts/
cp SafeLine_Push/mark/config.json /var/scripts/
```

### 配置文件说明
`config.json` 示例：
```json
{
    "DingTalk": {
        "WebHook": "https://oapi.dingtalk.com/robot/send?access_token=your_token",
        "Secret": "your_secret"
    }
}
```

`VulConfig.json` 规则片段：
```json
{
    "replacements": {
        "m_sqli": "SQL注入",
        "m_xss": "跨站脚本攻击"
    },
    "whitelist": ["合法爬虫UA"]
}
```

## 📊 使用效果
### 攻击告警示例
![攻击告警](https://zone.huoxian.cn/uploads/202401/1705990599-6583b2e79f9f5.png)

### 封禁通知示例
![封禁通知](https://zone.huoxian.cn/uploads/202401/1705990600-6583b2e8e0a6d.png)

## ⚠️ 免责声明
本工具仅限合法安全测试用途，严禁用于任何违法活动。使用者需自行承担相关操作风险，继续使用视为同意该声明。

## 📎 相关资源
- [雷池社区版官网](https://waf-ce.chaitin.cn/)
- [原文教程](https://zone.huoxian.cn/d/2955-waf)
- [Docker文档](https://docs.docker.com/)

``` 
