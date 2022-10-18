package gosigner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"testing"
)

// TestRSAPrivKey testing para el metodo RSAPrivKey
func TestRSAPrivKey(t *testing.T) {

	defer deleteTestFiles()

	t.Run("TestRSAPrivKey", func(t *testing.T) {

		t.Run("Empty", func(t *testing.T) {

			key, err := RSAPrivKey([]byte(""))
			if err == nil {
				t.Errorf("Se esperaba un error")
				return
			}
			if err.Error() != "no se pudo decodificar el certificado" {
				t.Errorf("Se esperaba un error de tipo: no se pudo decodificar el certificado")
			}

			if err := key.Validate(); err == nil {
				t.Errorf("Se esperaba un error validando la llave vacía")
			} else if err.Error() != "crypto/rsa: missing public modulus" {
				t.Errorf("Se esperaba un error de tipo: crypto/rsa: missing public modulus")
			}
		})

		t.Run("Not_Certificate", func(t *testing.T) {

			_, err := RSAPrivKey([]byte("Not_Certificate"))
			if err == nil {
				t.Errorf("Se esperaba un error")
				return
			}
			if err.Error() != "no se pudo decodificar el certificado" {
				t.Errorf("Se esperaba un error de tipo: no se pudo decodificar el certificado")
			}
		})

		t.Run("No_RSA_Certificate", func(t *testing.T) {

			// Genera una llave privada RSA para el test
			privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Errorf("No se pudo generar la llave privada: %+v", err)
				return
			}
			var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
			privateKeyBlock := &pem.Block{
				Type:  "NO RSA PRIVATE KEY",
				Bytes: privateKeyBytes,
			}
			// Genera el certificado en formato pem
			privatePem, err := os.Create("private.pem")
			if err != nil {
				t.Errorf("No se pudo crear el archivo private.pem: %+v", err)
				return
			}
			// Se escribe el certificado en el archivo
			err = pem.Encode(privatePem, privateKeyBlock)
			if err != nil {
				t.Errorf("No se pudo generar el certificado: %+v", err)
				return
			}
			// Se cierra el archivo
			if err := privatePem.Close(); err != nil {
				t.Errorf("No se pudo cerrar el archivo private.pem: %+v", err)
				return
			}
			// leemos el archivo del certificado
			content, err := os.ReadFile("private.pem")
			if err != nil {
				t.Errorf("No se pudo leer el archivo private.pem: %+v", err)
				return
			}
			_, err = RSAPrivKey(content)
			if err == nil {
				t.Errorf("Debería haber error: %+v", err)
				return
			}
			if err.Error() != "el certificado no es RSA" {
				t.Errorf("Se esperaba un error diferente: %+v", err)
			}
		})

		t.Run("RSA_Certificate", func(t *testing.T) {

			// Genera una llave privada RSA para el test
			privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Errorf("No se pudo generar la llave privada: %+v", err)
				return
			}
			var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
			privateKeyBlock := &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privateKeyBytes,
			}
			// Genera el certificado en formato pem
			privatePem, err := os.Create("private.pem")
			if err != nil {
				t.Errorf("No se pudo crear el archivo private.pem: %+v", err)
				return
			}
			// Se escribe el certificado en el archivo
			err = pem.Encode(privatePem, privateKeyBlock)
			if err != nil {
				t.Errorf("No se pudo generar el certificado: %+v", err)
				return
			}
			// Se cierra el archivo
			if err := privatePem.Close(); err != nil {
				t.Errorf("No se pudo cerrar el archivo private.pem: %+v", err)
				return
			}
			// leemos el archivo del certificado
			content, err := os.ReadFile("private.pem")
			if err != nil {
				t.Errorf("No se pudo leer el archivo private.pem: %+v", err)
				return
			}
			key, err := RSAPrivKey(content)
			if err != nil {
				t.Errorf("No debería haber error: %+v", err)
				return
			}
			if err := key.Validate(); err != nil {
				t.Errorf("Error validando la llave %+v", err)
				return
			}
		})
	})
}

// Eliminar archivos generados para el test
func deleteTestFiles() {

	if err := os.Remove("private.pem"); err != nil {
		log.Printf("No se pudo eliminar el archivo private.pem: %+v", err)
	}
}
