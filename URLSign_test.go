package gosigner

import (
	"strings"
	"testing"
)

func TestURLSign(t *testing.T) {

	t.Run("TestURLSign", func(t *testing.T) {

		t.Run("Empty", func(t *testing.T) {

			sign := URLSign([]byte(""), []byte(""))
			if sign == "" {
				t.Errorf("El hash resumen no debería estar vacío")
				return
			}
			if sign != "thNnmggU2ex3L5XXeMNfxf8Wl8STcVZTxscSFEKSxa0" {
				t.Errorf("El hash resumen no es el esperado, se obtuvo: %s", sign)
			}
		})

		t.Run("No_Empty", func(t *testing.T) {

			data := "Cññh1==213123s,..aadaasdfsccddddffffsa3wwesdadaafsdafsCiqHñññh1==s,..aasd"
			sign := URLSign([]byte(data), []byte("15555"))
			if sign == "" {
				t.Errorf("El hash no debería estar vacío")
			}
			if strings.ContainsAny(sign, "=/+") {
				t.Errorf("El hash no es url Safe")
			}
		})
	})
}
