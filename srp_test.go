package srp

import (
	"crypto/sha1"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test vector from https://www.ietf.org/rfc/rfc5054.txt
var username = "alice"
var password = "password123"
var salt = GetBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
var prime = GetBigIntFromHex("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3")
var generator = GetBigIntFromHex("2")
var multiplier = GetBigIntFromHex("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
var x = GetBigIntFromHex("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
var xWithoutUsername = GetBigIntFromHex("BF56D7DF 933FF138 C4ED956E 26D2576D BBE8530B")
var verifier = GetBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
var privateClientValue = GetBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
var privateServerValue = GetBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
var publicClientValue = GetBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")
var publicServerValue = GetBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")
var scramblingParameter = GetBigIntFromHex("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")
var premasterSecret = GetBigIntFromHex("B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D 233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C 41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F 3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D C346D7E4 74B29EDE 8A469FFE CA686E5A")
var clientEvidence = GetBigIntFromHex("B46A7838 46B7E569 FF8F9B44 AB8D88ED EB085A65")
var serverEvidence = GetBigIntFromHex("B0A6AD30 24E79b5C AD04042A BB3A3F59 2D20C17")

func TestWithVector(t *testing.T) {
	var h = sha1.New()

	assert.Equal(t, multiplier, ComputeMultiplier(h, prime, generator))
	assert.Equal(t, x, ComputeXWithUsername(h, salt, username, password))
	assert.Equal(t, scramblingParameter, ComputeScramblingParameter(h, prime, publicClientValue, publicServerValue))
	assert.Equal(t, verifier, ComputeVerifier(prime, generator, x))
	assert.Equal(t, publicClientValue, ComputePublicClientValue(prime, generator, privateClientValue))
	assert.Equal(t, publicServerValue, ComputePublicServerValue(prime, generator, multiplier, verifier, privateServerValue))
	assert.Equal(t, premasterSecret, ComputeServerSessionKey(prime, verifier, scramblingParameter, publicClientValue, privateServerValue))
	assert.Equal(t, premasterSecret, ComputeClientSessionKey(prime, generator, multiplier, x, scramblingParameter, privateClientValue, publicServerValue))
}

func TestGenerateRandomSalt(t *testing.T) {
	var r = rand.New(rand.NewSource(time.Now().UnixNano()))

	var salt []byte
	for i := 0; i < 100; i++ {
		salt = GenerateRandomSalt(r, i)
		assert.Equal(t, i, len(salt))
	}
}

func TestComputeXWithoutUsername(t *testing.T) {
	var h = sha1.New()

	var x = ComputeXWithoutUsername(h, salt, username, password)
	assert.Equal(t, xWithoutUsername, x)
}

func TestGeneratePrivateValue(t *testing.T) {
	var r = rand.New(rand.NewSource(time.Now().UnixNano()))
	var min = big.NewInt(1)
	var max = prime

	for i := 0; i < 1e6; i++ {
		var v = GeneratePrivateValue(r, prime)
		// v >= min
		assert.True(t, v.Cmp(min) == 0 || v.Cmp(min) == 1)
		// v < max
		assert.True(t, v.Cmp(max) == -1)
	}
}

func TestIsValidPublicValue(t *testing.T) {
	// Test with valid values.
	assert.True(t, IsValidPublicValue(prime, publicClientValue))
	assert.True(t, IsValidPublicValue(prime, publicServerValue))

	// Test with invalid values (x % n == 0)
	var x = big.NewInt(0)
	for i := 0; i < 100; i++ {
		assert.False(t, IsValidPublicValue(prime, x))
		x = x.Add(x, prime)
	}
}

func TestComputeClientEvidence(t *testing.T) {
	var h = sha1.New()

	var e = ComputeClientEvidence(h, publicClientValue, publicServerValue, premasterSecret)
	assert.Equal(t, clientEvidence, e)
}

func TestComputeServerEvidence(t *testing.T) {
	var h = sha1.New()

	var e = ComputeServerEvidence(h, publicClientValue, clientEvidence, premasterSecret)
	assert.Equal(t, serverEvidence, e)
}

func TestGetGroup(t *testing.T) {
	// Test with valid group name.
	var grpNames = []string{"rfc-1024", "rfc-1536", "rfc-2048", "rfc-3072", "rfc-4096", "rfc-6144", "rfc-8192"}

	for _, grpName := range grpNames {
		var grp, err = GetGroup(grpName)
		assert.Nil(t, err)
		assert.NotNil(t, grp.Prime)
		assert.NotNil(t, grp.Generator)
	}

	// Test with invalid group name.
	var grp, err = GetGroup("invalid")
	assert.NotNil(t, err)
	assert.Nil(t, grp)
}

func TestGetBigIntFromHex(t *testing.T) {
	var validValues = []string{"0", "ab", "AbC", "0    a"}

	for _, v := range validValues {
		var x = GetBigIntFromHex(v)
		assert.NotNil(t, x)
	}

	var invalidValues = []string{"", "abcdefg", "012%"}

	for _, v := range invalidValues {
		var f = func() {
			_ = GetBigIntFromHex(v)
		}
		assert.Panics(t, f)
	}

}
