package sso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"math/big"
)

const (
	//ES256 keys
	ECDSAKeyD = "3999161F60FCAE8D34E05D55F7C07ED9C761CCC102EA75C42C1C5483A6FEBCB"
	ECDSAKeyX = "C2124438109F89DB29063DAF3C66CDBC31A9D4E2292652997127663DB219429"
	ECDSAKeyY = "3868441F8D52D78EDD5396182C72B58E71F96BE758B28C1775C4813FAC86929"

	//HS256 signed key
	SIGNED_KEY = "HSSignedKey"
)

//获取签名算法为ES256的token
//该token的内容只有Redis的key,用于保存用户的登录状态
func GetEStoken(redisKey string) (string, error) {
	keyD := new(big.Int)
	keyX := new(big.Int)
	keyY := new(big.Int)

	keyD.SetString(ECDSAKeyD, 16)
	keyX.SetString(ECDSAKeyX, 16)
	keyY.SetString(ECDSAKeyY, 16)

	claims := jwt.MapClaims{
		"redisKey": redisKey,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     keyX,
		Y:     keyY,
	}

	privateKey := ecdsa.PrivateKey{D: keyD, PublicKey: publicKey}

	ss, err := token.SignedString(&privateKey)
	if err != nil {
		return "", errors.New("EStoken生成签名错误")
	}
	return ss, nil
}

//获取签名算法为HS256的token
func GetHStoken(tokenFirst string, user map[string]interface{}) (string, error) {

	var claims = jwt.MapClaims{}
	claims["id"] = tokenFirst
	for k, v := range user {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(SIGNED_KEY))
	if err != nil {
		return "", errors.New("token生成签名错误")
	}
	return ss, nil
}

//解析签名算法为ES256的token
func ParseEStoken(tokenES string) (string, error) {
	keyX := new(big.Int)
	keyY := new(big.Int)

	keyX.SetString(ECDSAKeyX, 16)
	keyY.SetString(ECDSAKeyY, 16)

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     keyX,
		Y:     keyY,
	}

	token, err := jwt.Parse(tokenES, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &publicKey, nil
	})
	if err != nil {
		return "", errors.New("ES256的token解析错误")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["redisKey"].(string), nil
	}

	return "", errors.New("ParseEStoken:Claims类型转换失败")
}

//解析签名算法为HS256的token
func ParseHStoken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(SIGNED_KEY), nil
	})
	if err != nil {
		return nil, errors.New("HS256的token解析错误")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("ParseHStoken:claims类型转换失败")
	}
	return claims, nil
}
