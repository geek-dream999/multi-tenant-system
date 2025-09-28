package utils

import (
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/flipped-aurora/gin-vue-admin/server/global"
	"go.uber.org/zap"
)

var (
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	once                 sync.Once
)

// GetCasbin 获取casbin实例
func GetCasbin() *casbin.SyncedCachedEnforcer {
	once.Do(func() {
		a, err := gormadapter.NewAdapterByDB(global.GVA_DB)
		if err != nil {
			zap.L().Error("适配数据库失败请检查casbin表是否为InnoDB引擎!", zap.Error(err))
			return
		}
		text := `
          [request_definition]
          r = sub, dom, obj, act
          
          [policy_definition]
          p = sub, dom, obj, act
          
          [role_definition]
          g = _, _, _
          
          [policy_effect]
          e = some(where (p.eft == allow))
          
          [matchers]
          # Allow if:
          #  - policy domain is "*" (global) OR equals request domain
          #  - AND subject has role in the domain (or in "*" global domain)
          #  - AND object match & action match
          m = (p.dom == "*" || p.dom == r.dom) && (g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "*")) && keyMatch2(r.obj, p.obj) && r.act == p.act
          `

		m, err := model.NewModelFromString(text)
		if err != nil {
			zap.L().Error("Casbin 模型加载失败!", zap.Error(err))
			return
		}

		syncedCachedEnforcer, err = casbin.NewSyncedCachedEnforcer(m, a)
		if err != nil {
			zap.L().Error("Casbin Enforcer 初始化失败!", zap.Error(err))
			return
		}

		syncedCachedEnforcer.SetExpireTime(60 * 60)
		if err := syncedCachedEnforcer.LoadPolicy(); err != nil {
			zap.L().Error("加载策略失败!", zap.Error(err))
		}
	})
	return syncedCachedEnforcer
}
