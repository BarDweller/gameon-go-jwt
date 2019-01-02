package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestTestToken(t *testing.T) {

	//create test keypair
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("Unable to build key")
	}

	//construct gojwt with test keypair
	gojwt := GoJWT{PrivateKey: key, PublicKey: &key.PublicKey}

	//create test jwt.
	testjwt := gojwt.CreateTestJwt()

	//parse it back to struct
	token, err := jwt.Parse(testjwt, func(token *jwt.Token) (interface{}, error) { return &key.PublicKey, nil })

	if err != nil {
		t.Fatal(fmt.Sprintf("Unable to parse test JWT: %s", err))
	}

	//obtain claims map from token
	claims := token.Claims.(jwt.MapClaims)

	//verify audience
	if claims["aud"] != "client" {
		t.Log("Test JWT did not have audience client")
		t.Fail()
	}
}

func TestUpgradeToken(t *testing.T) {
	//create test keypair
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("Unable to build key")
	}

	//construct gojwt with test keypair
	gojwt := GoJWT{PrivateKey: key, PublicKey: &key.PublicKey}

	//create test jwt.
	testjwt := gojwt.CreateTestJwt()
	//upgrade test jwt.
	testjwt, err = gojwt.UpgradeJwt(testjwt)

	//parse it back to struct
	token, err := jwt.Parse(testjwt, func(token *jwt.Token) (interface{}, error) { return &key.PublicKey, nil })
	if err != nil {
		t.Fatal(fmt.Sprintf("Unable to parse test JWT: %s", err))
	}

	//obtain claims map from token
	claims := token.Claims.(jwt.MapClaims)

	//verify audience
	if claims["aud"] != "server" {
		t.Error("Test JWT did not have audience server")
	}
}

func TestEnforceRSToken(t *testing.T) {
	hstoken := "eyJhbGciOiJIUzI1NiIsImtpZCI6InBsYXllcnNzbCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjbGllbnQiLCJlbWFpbCI6ImRldnVzZXJAZHVtbXllbWFpbC5jb20iLCJleHAiOjE1NDY0NTc0MzIsImlhdCI6MTU0NjI4NDYzMiwiaWQiOiJkdW1teS5EZXZVc2VyIiwibmFtZSI6IkRldlVzZXIiLCJzdWIiOiJkdW1teS5EZXZVc2VyIn0.hW7v7fx8FHuHGdkC8uo5yrItwQ-dyzcglCnZXYBm8g8"
	gojwt := GoJWT{}

	fmt.Println(hstoken)
	//upgrade test jwt.
	_, err := gojwt.UpgradeJwt(hstoken)

	fmt.Println(err)

	if err == nil {
		t.Log("error HS256 Token accepted for upgrade")
		t.Fail()
	}
}
