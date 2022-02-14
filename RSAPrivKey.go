package gosigner

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
)

// RSAPrivKey Genera un rsa.PrivateKey a partir de un arreglo de bytes que represente un certificado.pem
// privado RSA y su respectiva contraseña
// Deprecation
func RSAPrivKey(s []byte) (key rsa.PrivateKey, err error) {

	p, _ := pem.Decode(s)
	if p == nil {
		return key, errors.New("no se pudo decodificar el certificado")
	}
	if p.Type != "RSA PRIVATE KEY" {

		err = errors.New("el certificado no es RSA")
		return
	}

	if err != nil {

		return
	}

	var parsed interface{}
	if parsed, err = x509.ParsePKCS1PrivateKey(p.Bytes); err != nil {

		if parsed, err = x509.ParsePKCS8PrivateKey(p.Bytes); err != nil {

			err = errors.New("no se puede parsear el certificado RSA proporcionado")
			return
		}
	}

	log.Printf("parsed: %+v", parsed)
	switch kind := parsed.(type) {
	case *rsa.PrivateKey:
		key = *kind
	default:
		err = errors.New("la llave privada no es del tipo RSA")
	}
	return
}
