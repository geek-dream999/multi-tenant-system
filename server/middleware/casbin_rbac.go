package middleware

import (
	"strconv"
	"strings"

	"github.com/flipped-aurora/gin-vue-admin/server/global"
	"github.com/flipped-aurora/gin-vue-admin/server/model/common/response"
	"github.com/flipped-aurora/gin-vue-admin/server/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CasbinHandler 拦截器
func CasbinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从上下文获取租户 ID（假设整形）
		/*tidI, exists := c.Get("tenant_id")
		if !exists {
			// 如果没有 tenant，按策略拒绝或给默认租户
			response.FailWithDetailed(gin.H{}, "租户标识缺失", c)
			c.Abort()
			return
		}
		// 把 domain 转为字符串形式（Casbin 的 domain 用字符串）
		var domain string
		switch v := tidI.(type) {
		case int:
			domain = strconv.Itoa(v)
		case int64:
			domain = strconv.FormatInt(v, 10)
		case string:
			domain = v
		default:
			domain = fmt.Sprintf("%v", v)
		}*/

		// 获取 user / sub（这里用你的 AuthorityId，或可改为用户名/ID string）
		waitUse, _ := utils.GetClaims(c)
		sub := strconv.Itoa(int(waitUse.AuthorityId))

		domain := strconv.Itoa(int(waitUse.TenantId))
		// 打印日志  casbin sub domain obj act
		// 获取请求路径、方法
		path := c.Request.URL.Path
		// obj 要 “去前缀” 的处理（同你原来那样）
		obj := strings.TrimPrefix(path, global.GVA_CONFIG.System.RouterPrefix)
		act := c.Request.Method
		zap.L().Info("casbin sub domain obj act", zap.String("sub", sub), zap.String("domain", domain), zap.String("obj", obj), zap.String("act", act))

		// 调用 Casbin：改为带 domain 的 enforce
		e := utils.GetCasbin()
		ok, err := e.Enforce(sub, domain, obj, act)
		if err != nil {
			// 如果 enforce 出错，记录日志、返回错误
			zap.L().Error("casbin enforce error", zap.Error(err))
			response.FailWithDetailed(gin.H{}, "权限校验异常", c)
			c.Abort()
			return
		}
		if !ok {
			response.FailWithDetailed(gin.H{}, "权限不足", c)
			c.Abort()
			return
		}

		c.Next()
	}
}
