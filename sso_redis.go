package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xinglou123/pkg/db/redis"
	"time"
)

// RedisPool Redis连接池
var RedisOptions *redis.Options

func init() {
	fmt.Println("sso_redis init")
	RedisOptions = &redis.Options{
		Host:                "localhost",
		Port:                6379,
		ConnectionMaxIdle:   10,
		ConnectionMaxActive: 10,
		ConnectionWait:      true,
		ConnectTimeout:      240 * time.Second,
	}

}

//
func ClaimsFromRedis(sid string) (SSOClaims, error) {

	client := redis.SetupClient(RedisOptions)
	defer client.Close()

	claims, _, err := client.Get(sid)
	if err != nil {
		return SSOClaims{}, errors.New(err.Error())
	}
	var ssoclaim SSOClaims
	bytesErr := json.Unmarshal([]byte(claims), &ssoclaim)
	return ssoclaim, bytesErr
}

//
func ClaimsToRedis(claims SSOClaims) (bool, error) {

	userBytes, err := json.Marshal(claims)
	if err != nil {
		return false, errors.New("claimsToRedis error")
	}
	client := redis.SetupClient(RedisOptions)
	defer client.Close()

	return client.SetEx(claims.SSOId, string(userBytes), claims.SSOExpired)
}

//
func RefreshClaimsExpire(sid string, expired int64) (bool, error) {
	client := redis.SetupClient(RedisOptions)
	defer client.Close()
	return client.Expire(sid, expired)
}

//
func RemoveClaims(sid string) (int64, error) {
	client := redis.SetupClient(RedisOptions)
	defer client.Close()
	return client.Del(sid)
}
