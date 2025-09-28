package request

// CasbinInfo Casbin info structure
type CasbinInfo struct {
	TenantId uint   `json:"tenantId"`
	Path     string `json:"path"`   // 路径
	Method   string `json:"method"` // 方法
}

// CasbinInReceive Casbin structure for input parameters
type CasbinInReceive struct {
	AuthorityId uint         `json:"authorityId"` // 权限id
	CasbinInfos []CasbinInfo `json:"casbinInfos"`
}

func DefaultCasbin() []CasbinInfo {
	return []CasbinInfo{
		{Path: "/menu/getMenu", Method: "POST", TenantId: 1},
		{Path: "/jwt/jsonInBlacklist", Method: "POST", TenantId: 1},
		{Path: "/base/login", Method: "POST", TenantId: 1},
		{Path: "/user/changePassword", Method: "POST", TenantId: 1},
		{Path: "/user/setUserAuthority", Method: "POST", TenantId: 1},
		{Path: "/user/getUserInfo", Method: "GET", TenantId: 1},
		{Path: "/user/setSelfInfo", Method: "PUT", TenantId: 1},
		{Path: "/fileUploadAndDownload/upload", Method: "POST", TenantId: 1},
		{Path: "/sysDictionary/findSysDictionary", Method: "GET", TenantId: 1},
	}
}
