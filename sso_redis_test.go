package sso

import (
	"fmt"
	"testing"
)

func TestRedis(t *testing.T) {
	//var claims = SSOClaims{
	//	SSOId:"123",
	//	SSOKeys: map[string]interface{}{"id":123,"name":"liuchengbin"},
	//	SSOExpired:10,
	//}
	//token,_:=ClaimsToRedis(claims)
	//println(token)

	claimsv, _ := ClaimsFromRedis("123")
	//println(err.Error())
	fmt.Println(claimsv)
	//println(claimsv.SSOId)
	//println(claimsv.SSOKeys["name"].(string))
	//println(claimsv.SSOExpired)

}
