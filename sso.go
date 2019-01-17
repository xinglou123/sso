package sso

import (
	"github.com/xinglou123/pkg/os/uuid"
	"sync"
)

const DEFAULT_Expire = 24 * 60 * 60

type SSO struct {
}

var sso *SSO
var once sync.Once

func SSOShare() *SSO {
	once.Do(func() {
		sso = &SSO{}
	})
	return sso
}

//
func (ss *SSO) GenSSOToken(data map[string]interface{}) (string, error) {
	var claims SSOClaims
	claims.SSOId = uuid.UUid()
	claims.SSOExpired = DEFAULT_Expire
	claims.SSOKeys = data

	ssotoken, err := NewSSOToken().CreateToken(claims)
	if err != nil {
		return ssotoken, err
	}
	if ok, _ := ClaimsToRedis(claims); ok {
		return ssotoken, nil
	}
	return "", err
}

//
func (ss *SSO) PraseSSOToken(token string) (map[string]interface{}, error) {
	if len(token) == 0 {
		return nil, nil
	}
	sclaims, err := NewSSOToken().ParseToken(token)
	if err != nil {
		return nil, err
	}
	rclaims, err := ClaimsFromRedis(sclaims.SSOId)
	if err != nil {
		return nil, err
	}
	return rclaims.SSOKeys, nil
}

//
func (ss *SSO) ExpireSSOToken(sid string, expired int64) (bool, error) {
	if len(sid) == 0 {
		return false, nil
	}
	if expired <= 0 {
		expired = DEFAULT_Expire
	}
	return RefreshClaimsExpire(sid, expired)
}

//
func (ss *SSO) RemoveSSOToken(sid string) (int64, error) {
	if len(sid) == 0 {
		return 0, nil
	}
	return RemoveClaims(sid)
}
