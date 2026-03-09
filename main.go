package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/zalando/go-keyring"
)

const ValidityDuration = 30
const Service = "otp"

var (
	add  = flag.Bool("add", false, "Add a provider and a secret key.")
	help = flag.Bool("help", false, "Get help.")
)

func main() {
	flag.Parse()
	if *help {
		printHelpText()
		return
	}
	if *add {
		addProviderAndSecret()
		return
	}

	token := getSecretToken()
	fmt.Println(token)
}

func printHelpText() {
	text := `
	- To add a new provider and a secret key:

		Please follow the format below:
		otp -add <provider> <secret-key>

		Example:
		otp -add github JBSWY3DPEHPK3PXP

	- To get your Time-based One-time password:
		Please follow the format below:
		otp <provider> 

		Example:
		otp github
`
	fmt.Println(text)
}

func getSecretToken() int {
	if len(flag.Args()) < 1 {
		log.Fatal(`
			The name of a provider is missing. 

			Please follow the format below:
			otp <provider> 

			Example:
			otp github

			For more info: 
			otp -help

		`)
	}
	provider := flag.Args()[0]
	secret := getSecret(provider)
	return genToken(secret)
}

func addProviderAndSecret() {
	if len(flag.Args()) < 2 {
		log.Fatal(`
			Either the name of a provider or a secret key is missing. 

			Please follow the format below:
			otp -add <provider> <secret-key>

			Example:
			otp -add github JBSWY3DPEHPK3PXP


			For more info: 
			otp -help

		`)
	}
	provider := flag.Args()[0]
	secret := flag.Args()[1]
	setSecret(provider, secret)
}

// setSecret safely saves provider and the secret key in the keyring.
func setSecret(provider, secret string) {
	err := keyring.Set(Service, provider, secret)
	if err != nil {
		log.Fatal(err)
	}
}

// getSecret retrieves the secret key from the keyring.
func getSecret(provider string) string {
	secret, err := keyring.Get(Service, provider)
	if err != nil {
		if err == keyring.ErrNotFound {
			log.Fatal(`
				Sorry, provider not found. 
				Please make sure you have entered the correct spelling.
				Or, add a new one, if you haven't.


				For more info: 
			        otp -help

				`)
		}
	}
	return secret
}

// genToken generates HMAC hash (using SHA1) with the secret and the counterBytes (see getCounterBytes()).
// Then, extracts 4 bytes from that hash, and converts them into a number with 6 digits — the TOTP.
func genToken(secret string) int {
	c := getCounterBytes()
	d := decode(secret)

	// Create a new Has interface, and setup sha1 as a hash function,
	// along with the decoded secret key as the key.
	macHash := hmac.New(sha1.New, d)

	// Pass counter bytes as the message to be hashed.
	macHash.Write(c)

	// Get the final hash result.
	//
	// This 160-bit (20byte) value will be in a Hexadecimal format,
	// and needs to be truncated to 31 bit using dynamic truncation.
	hash := macHash.Sum(nil)

	// Extract 4 bytes (using dynamic truncation — follow the link below for more info)
	// https://www.ionos.com/digitalguide/server/security/totp/#:~:text=HMAC%20(with%20SHA%2D1),starting%20at%200):%200x377a3af0.
	//

	// Get the offset value from the last 4 bits.
	// And perform a bitwise AND operation with 0x0f — equals 15 in decimal.
	offset := hash[19] & 0x0f

	// Convert these 4 bytes into a 31-bit value
	// using binary.BigEndian to read 4 bytes as a uint32
	tValue := int(binary.BigEndian.Uint32(hash[offset:offset+4])) & 0x7fffffff

	// Reduce 9-digit string to 6 digits using a modulo operation.
	return tValue % 1_000_000 // mod (10 to the power of 6)
}

func decode(secret string) []byte {
	d, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		log.Fatal(err)
	}
	return d
}

func getCounterBytes() []byte {
	// Generate the counter value.
	// Unix time as an integer divided by a valid duration (by default, 30 seconds).
	counterValue := (time.Now().Unix()) / int64(ValidityDuration)
	// Below, the length of the bytes specify how many bytes to use to represent time.
	// 8 means 64 bits.
	counterBytes := make([]byte, 8)
	// Write the counterValue into they byte array — counterBytes.
	binary.BigEndian.PutUint64(counterBytes, uint64(counterValue))
	return counterBytes
}

// genSecretKey generates a secure TOTP secret key of 16 characters.
func genSecretKey() string {
	b := genRandBytes(10) // 10 bytes.
	// Encode into Base32
	return base32.StdEncoding.EncodeToString(b)
}

// genRandBytes generates cryptographically secure n random bytes
func genRandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return b
}
