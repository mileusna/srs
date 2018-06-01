package srs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/mail"
	"strings"
	"time"
	"unicode"
)

// SRS engine
type SRS struct {
	// Secret key, mandatory
	Secret []byte
	// Domain is localhost which will forward the emails
	Domain string
	// MaxAge in days for timestamp validity check. Optional, default 21
	MaxAge int
	// HashLength optional, default = 4
	HashLength int

	defaultsChecked bool
}

// Forward returns SRS forward address or error
func (srs *SRS) Forward(email string) (string, error) {
	if !srs.defaultsChecked {
		srs.setDefaults()
	}

	local, hostname, err := parseEmail(email)
	if err != nil {
		return "", err
	}

	//SRS0=8Zzm=IS=netmark.rs=milos@localhost.localdomain

	ts := base32Encode(timestamp())
	return fmt.Sprintf("SRS0=%s=%s=%s=%s@%s", srs.hash([]byte(strings.ToLower(ts+hostname+local))), ts, hostname, local, srs.Domain), nil
}

// Reverse the SRS email address to regular email addresss or error
func (srs *SRS) Reverse(email string) (string, error) {
	if !srs.defaultsChecked {
		srs.setDefaults()
	}

	srs0, _, err := parseEmail(email)
	if err != nil {
		return "", errors.New("Not an SRS address")
	}

	if !strings.HasPrefix(srs0, "SRS0=") {
		return "", errors.New("Not an SRS address")
	}

	parts := strings.SplitN(srs0, "=", 5)
	if len(parts) < 5 {
		return "", errors.New("No user in SRS0 address")
	}

	if err := srs.checkTimestamp(parts[2]); err != nil {
		return "", err
	}

	if parts[1] != srs.hash([]byte(strings.ToLower(parts[2]+parts[3]+parts[4]))) {
		return "", errors.New("Hash invalid in SRS address")
	}

	return parts[4] + "@" + parts[3], nil
}

func (srs SRS) hash(input []byte) string {
	mac := hmac.New(sha1.New, srs.Secret)
	mac.Write(input)
	s := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return s[:srs.HashLength]
}

// setDefaults parameters if not set
func (srs *SRS) setDefaults() {
	if srs.MaxAge == 0 {
		srs.MaxAge = 21
	}

	if srs.HashLength == 0 {
		srs.HashLength = 4
	}

	srs.defaultsChecked = true
}

// parseEmail and return username and domain name
func parseEmail(e string) (user, domain string, err error) {
	addr, err := mail.ParseAddress(e)
	if err == nil {
		parts := strings.SplitN(addr.Address, "@", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}
	return "", "", errors.New("Bad formated email address")
}

const (
	timePrecision = float64(60 * 60 * 24)
	timeSlots     = float64(1024) // dont make mistakes like 2 ^ 10, since in go ^ is not power operator
)

// timestamp integer
func timestamp() int {
	t := float64(time.Now().Unix())
	x := math.Mod(t/timePrecision, timeSlots)
	return int(x)
}

// checkTimestamp validity for illegal characters and out of date timestamp
func (srs *SRS) checkTimestamp(ts string) error {
	// decode base32 encoded timestamp to `then``
	then := 0
	for _, c := range ts {
		pos := strings.IndexRune(base32, unicode.ToUpper(c))
		if pos == -1 {
			return errors.New("Bad base32 character in timestamp")
		}
		then = then<<5 | pos
	}

	now := timestamp()

	// mind the cycle of time slots
	for now < then {
		now = now + int(timeSlots)
	}

	if now <= then+srs.MaxAge {
		return nil
	}

	return errors.New("Time stamp out of date")
}

const (
	base32   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	baseSize = 32
)

// base32Encode integer to string
func base32Encode(x int) (encoded string) {
	for x > 0 {
		r := x % baseSize
		x /= baseSize
		encoded = string(base32[r]) + encoded
	}
	return encoded
}
