package seal_test

import (
	"fmt"

	"github.com/govengers/auth/seal"
)

// The ring comes from configuration, e.g. SEAL_KEYS, primary key first. Rotate by putting a new key in front,
// resealing every value, then dropping the old key.
func Example() {
	keys, err := seal.ParseKeys("2026-11:c2VhbC1leGFtcGxlLWtleS0yMDI2LTExLTAwMDAwMDA,2026-01:c2VhbC1leGFtcGxlLWtleS0yMDI2LTAxLTAwMDAwMDA")
	if err != nil {
		fmt.Println(err)
		return
	}
	sealer, err := seal.New(&seal.Options{Keys: keys})
	if err != nil {
		fmt.Println(err)
		return
	}
	webhookSecret := seal.AssociatedData{Purpose: "webhook_signing_secret", Table: "webhooks", Row: "0195f7a2-webhook"}
	sealed, err := sealer.Seal(webhookSecret, []byte("whsec_example"))
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext, err := sealer.Open(webhookSecret, sealed)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = sealer.Open(seal.AssociatedData{Purpose: "webhook_signing_secret", Table: "webhooks", Row: "another-row"}, sealed)
	fmt.Println(string(plaintext))
	fmt.Println(err)
	// Output:
	// whsec_example
	// open sealed value of key "2026-11": seal: sealed value is malformed, tampered with or bound to other data
}
