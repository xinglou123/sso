package sso

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
)

var (
	SignKey string = "LiuChengBin"
)

type SSOClaims struct {
	SSOId      string                 `json:"sso_id"`
	SSOKeys    map[string]interface{} `json:"sso_keys"`
	SSOExpired int64                  `json:"sso_expired"`
	jwt.StandardClaims
}

type SSOToken struct {
	SigningKey []byte
}

func NewSSOToken() *SSOToken {
	return &SSOToken{
		[]byte(GetSignKey()),
	}
}
func GetSignKey() string {
	return SignKey
}
func SetSignKey(key string) string {
	SignKey = key
	return SignKey
}

//获取签名算法为HS256的token
func (st *SSOToken) CreateToken(claims SSOClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(st.SigningKey)
	if err != nil {
		return "", errors.New("token生成签名错误")
	}
	return ss, nil
}

//解析签名算法为HS256的token
func (st *SSOToken) ParseToken(tokenString string) (*SSOClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &SSOClaims{}, func(token *jwt.Token) (interface{}, error) {
		return st.SigningKey, nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("That's not even a token")
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, errors.New("Token is expired")
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, errors.New("Token not active yet")
			} else {
				return nil, errors.New("Couldn't handle this token:")
			}
		}
	}

	if claims, ok := token.Claims.(*SSOClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("SSOClaims:claims类型转换失败")

}
