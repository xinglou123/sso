package sso

const (
	//操作成功
	SSO_OK                    = "OK"
	SSO_UNMARSHAL_REQBODY_ERR = "unmarshal_reqbody_err"
	//数据库增删改查错误
	SSO_DB_CRUD_ERR  = "db_crud_err"
	SSO_NEW_USER_ERR = "new_user_err"

	//reids
	SSO_REDIS_ERR = "redis_err"

	//jwt
	SSO_TOKEN_ERR = "token_err"

	SSO_REQUEST_PARAM_ERR = "request_param_err"
)
