package sso

import (
	"github.com/xinglou123/pkg/db/redis"
)

const (
	//登录状态有效期  24*60*60s=86400
	DEFAULT_EXPIRATION = 4
)

func CreateToken(redisKey string, keys map[string]interface{}) (string, error) {
	tokenFirst, status := GetEStoken(redisKey)
	if status != nil {
		return "", status
	}
	tokenSecond, status := GetHStoken(tokenFirst, keys)
	if status != nil {
		return "", status
	}
	return tokenSecond, status
}

func ParseToken(token string) (string, error) {
	//解析第一层token
	claimsHS, status := ParseHStoken(token)
	if status != nil {
		return "", status
	}
	//TODO 第二层token采用ES256算法，但XYD没解决
	tokenES := claimsHS["id"].(string)
	//解析第二层token
	redisKey, status := ParseEStoken(tokenES)
	if status != nil {
		return "", status
	}
	return redisKey, nil
}

func IsLogin(redisKey string) (bool, error) {
	client := redis.DefaultClient()
	defer client.Close()
	return client.Exists(redisKey)
}
func RefreshKey(redisKey string) (bool, error) {
	client := redis.DefaultClient()
	defer client.Close()
	return client.SetEx(redisKey, "Raed Shomali", DEFAULT_EXPIRATION)
}
func RemoveKey(redisKey string) (int64, error) {
	client := redis.DefaultClient()
	defer client.Close()
	return client.Del(redisKey)
}
