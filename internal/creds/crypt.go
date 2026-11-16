// Package creds is T-0 rotation on the jump box: new passwords, their
// hashes for the agents (sha512-crypt for the system, NT for Samba), and
// the local store that alone holds the cleartext.
package creds

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strconv"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// SHA512Crypt is password hashed as glibc's "$6$" (Drepper's SHA-crypt):
// the salt is cut to 16 characters, rounds held to [1000, 999999999], and
// the rounds= field left out when it is the default 5000.
func SHA512Crypt(password, salt string, rounds int) string {
	if len(salt) > 16 {
		salt = salt[:16]
	}
	rounds = min(max(rounds, 1000), 999999999)
	pw, sl := []byte(password), []byte(salt)

	b := sha512.New()
	b.Write(pw)
	b.Write(sl)
	b.Write(pw)
	sumB := b.Sum(nil)

	a := sha512.New()
	a.Write(pw)
	a.Write(sl)
	for n := len(pw); n > 0; n -= 64 {
		a.Write(sumB[:min(n, 64)])
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			a.Write(sumB)
		} else {
			a.Write(pw)
		}
	}
	sumA := a.Sum(nil)

	dp := sha512.New()
	for range len(pw) {
		dp.Write(pw)
	}
	p := repeat(dp.Sum(nil), len(pw))

	ds := sha512.New()
	for range 16 + int(sumA[0]) {
		ds.Write(sl)
	}
	s := repeat(ds.Sum(nil), len(sl))

	for i := range rounds {
		c := sha512.New()
		if i&1 != 0 {
			c.Write(p)
		} else {
			c.Write(sumA)
		}
		if i%3 != 0 {
			c.Write(s)
		}
		if i%7 != 0 {
			c.Write(p)
		}
		if i&1 != 0 {
			c.Write(sumA)
		} else {
			c.Write(p)
		}
		sumA = c.Sum(nil)
	}

	out := []byte("$6$")
	if rounds != 5000 {
		out = append(out, "rounds="+strconv.Itoa(rounds)+"$"...)
	}
	out = append(out, salt...)
	out = append(out, '$')
	for i := range 21 {
		j, k, l := i, (i+21)%63, (i+42)%63
		if i%3 == 1 {
			j, k, l = k, l, j
		} else if i%3 == 2 {
			j, k, l = l, j, k
		}
		out = b64(out, sumA[j], sumA[k], sumA[l], 4)
	}
	return string(b64(out, 0, 0, sumA[63], 2))
}

func repeat(sum []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, sum[:min(len(sum), n-len(out))]...)
	}
	return out
}

func b64(out []byte, b2, b1, b0 byte, n int) []byte {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for range n {
		out = append(out, cryptAlphabet[w&0x3f])
		w >>= 6
	}
	return out
}

// NTHash is Samba's (and Windows') password hash: hex MD4 of the
// password in UTF-16LE.
func NTHash(password string) string {
	h := md4.New()
	for _, u := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(u), byte(u >> 8)})
	}
	return hex.EncodeToString(h.Sum(nil))
}

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Password is 20 random letters and digits: nothing a scorer's form or a
// shell would read differently.
func Password() string { return randomString(passwordAlphabet, 20) }

// Hash is password as sha512-crypt with a fresh 16-character salt.
func Hash(password string) string {
	return SHA512Crypt(password, randomString(cryptAlphabet, 16), 5000)
}

func randomString(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand does not fail on Linux
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}
