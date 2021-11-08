package gorsa

import (
	"encoding/base64"
)

// 公钥加密
func PublicEncrypt(data, publicKey string) ([]byte, error) {

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	rsadata, err := grsa.PubKeyENCTYPT([]byte(data))
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}

// 私钥加密
func PriKeyEncrypt(data, privateKey string) ([]byte, error) {

	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	rsadata, err := grsa.PriKeyENCTYPT([]byte(data))
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}

// 公钥解密
func PublicDecrypt(data, publicKey string) ([]byte, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	rsadata, err := grsa.PubKeyDECRYPT([]byte(databs))
	if err != nil {
		return nil, err
	}

	return rsadata, nil

}

// 私钥解密
func PriKeyDecrypt(data, privateKey string) ([]byte, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	rsadata, err := grsa.PriKeyDECRYPT([]byte(databs))
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}
