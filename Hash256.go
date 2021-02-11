package gosigner

import "crypto/sha256"

// Hash256 genera un resumen del slice de bytes recibido
func Hash256(raw []byte) (resume []byte, err error) {

	hash := sha256.New()
	_, err = hash.Write(raw)
	if err != nil {
		return
	}
	resume = hash.Sum(nil)
	return
}
