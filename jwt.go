package jwt

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type GoJWT struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func New(certpath, keypath string) GoJWT {
	keyData, _ := ioutil.ReadFile(keypath)
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	certData, _ := ioutil.ReadFile(certpath)
	cert, _ := jwt.ParseRSAPublicKeyFromPEM(certData)
	return GoJWT{key, cert}
}

func (j *GoJWT) CreateTestJwt() string {
	return j.CreateDetailedTestJwt("dummy.DevUser", "DevUser", "devuser@dummyemail.com")
}

func (j *GoJWT) CreateDetailedTestJwt(id, name, email string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"name":  name,
		"id":    id,
		"email": email,
		"sub":   id,
		"aud":   "client",
		"iat":   time.Now().UTC().Add(time.Hour * -12).Unix(),
		"exp":   time.Now().UTC().Add(time.Hour * 12).Unix(),
	})
	token.Header["kid"] = "playerssl"
	tokenstr, _ := token.SignedString(j.PrivateKey)
	return tokenstr
}

func (j *GoJWT) UpgradeJwt(oldjwt string) (string, error) {

	//read old token, to obtain claims.
	oldtoken, err := jwt.Parse(oldjwt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return j.PublicKey, nil
	})

	//if we failed to parse, exit here, most likely jwt has expired.
	if err != nil {
		//old jwt could not be parsed!
		return "", err
	}

	//upgrade token audience to server
	claims := oldtoken.Claims.(jwt.MapClaims)
	claims["aud"] = "server"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//add in kid header to emulate old jwt code =)
	token.Header["kid"] = "playerssl"

	//sign token
	tokenstr, _ := token.SignedString(j.PrivateKey)
	return tokenstr, nil
}
