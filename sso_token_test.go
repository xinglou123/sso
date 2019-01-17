package sso

import (
	"testing"
)

func TestToken(t *testing.T) {
	var claims = SSOClaims{
		SSOId:   "123",
		SSOKeys: map[string]interface{}{"id": 123, "name": "liuchengbin"},
	}
	token, _ := NewSSOToken().CreateToken(claims)
	println(token)

	claimsv, err := NewSSOToken().ParseToken(token)
	println(err.Error())
	println(claimsv.SSOId)
	println(claimsv.SSOKeys["name"].(string))

}
