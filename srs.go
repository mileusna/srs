package srs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
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
	// HashLength optional, default = 4
	HashLength int
	// FirstSeparator after SRS0, can be =+-, default is =
	FirstSeparator rune

	defaultsChecked bool
}

// // Forward returns SRS forward address or error
// func (srs *SRS) Forward(email string) (string, error) {
// 	srs.setDefaults()

// 	local, hostname, err := parseEmail(email)
// 	if err != nil {
// 		return "", err
// 	}

// 	switch local[:5] {
// 	case "SRS0=":
// 		parts := strings.SplitN(local, "=", 5)
// 		if len(parts) < 5 {
// 			return "", errors.New("No user in SRS0 address")
// 		}
// 		local = strings.TrimPrefix(local, "SRS0")
// 		hash := srs.hash([]byte(strings.ToLower(hostname + local)))
// 		return fmt.Sprintf("SRS1=%s=%s==%s=%s=%s=%s@%s", hash, hostname, parts[1], parts[2], parts[3], parts[4], srs.Domain), nil

// 	case "SRS1=":
// 		return "", errors.New("TODO")

// 	default:
// 		ts := base32Encode(timestamp())
// 		return fmt.Sprintf("SRS0=%s=%s=%s=%s@%s", srs.hash([]byte(strings.ToLower(ts+hostname+local))), ts, hostname, local, srs.Domain), nil
// 	}

// }

// Forward returns SRS forward address or error
func (srs *SRS) Forward(email string) (string, error) {
	srs.setDefaults()

	local, hostname, err := parseEmail(email)
	if err != nil {
		return "", err
	}

	if hostname == srs.Domain {
		return email, nil
	}

	switch local[:5] {
	case "SRS0=":
		return srs.rewriteSRS0(local, hostname)

	case "SRS1=":
		return srs.rewriteSRS1(local, hostname)

	default:
		return srs.rewrite(local, hostname)
	}

}

// rewrite email address
func (srs SRS) rewrite(local, hostname string) (string, error) {
	ts := base32Encode(timestamp())
	buff := bytes.Buffer{}
	buff.WriteString("SRS0=")
	buff.WriteString(srs.hash([]byte(strings.ToLower(ts + hostname + local))))
	buff.WriteRune('=')
	buff.WriteString(ts)
	buff.WriteRune('=')
	buff.WriteString(hostname)
	buff.WriteRune('=')
	buff.WriteString(local)
	buff.WriteRune('@')
	buff.WriteString(srs.Domain)
	return buff.String(), nil
}

// rewriteSRS0 rewrites SRS0 address to SRS1
func (srs SRS) rewriteSRS0(local, hostname string) (string, error) {
	parts := strings.SplitN(local, "=", 5)
	if len(parts) < 5 {
		return "", errors.New("No user in SRS0 address")
	}
	local = strings.TrimPrefix(local, "SRS0")
	hash := srs.hash([]byte(strings.ToLower(hostname + local)))
	buff := bytes.Buffer{}
	buff.WriteString("SRS1=")
	buff.WriteString(hash)
	buff.WriteRune('=')
	buff.WriteString(hostname)
	buff.WriteString("==")
	buff.WriteString(parts[1]) // hash from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[2]) // timestamp from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[3]) // local user from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[4]) // hostname from SRS0
	buff.WriteRune('@')
	buff.WriteString(srs.Domain)
	return buff.String(), nil
	//return fmt.Sprintf("SRS1=%s=%s==%s=%s=%s=%s@%s", hash, hostname, parts[1], parts[2], parts[3], parts[4], srs.Domain), nil
}

// rewriteSRS1 rewrites SRS1 address to new SRS1
func (srs SRS) rewriteSRS1(local, hostname string) (string, error) {
	parts := strings.SplitN(local, "=", 5)
	if len(parts) < 5 {
		return "", errors.New("No user in SRS0 address")
	}
	local = strings.TrimPrefix(local, "SRS0")
	hash := srs.hash([]byte(strings.ToLower(hostname + local)))
	buff := bytes.Buffer{}
	buff.WriteString("SRS1=")
	buff.WriteString(hash)
	buff.WriteRune('=')
	buff.WriteString(hostname)
	buff.WriteString("==")
	buff.WriteString(parts[1]) // hash from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[2]) // timestamp from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[3]) // local user from SRS0
	buff.WriteRune('=')
	buff.WriteString(parts[4]) // hostname from SRS0
	buff.WriteRune('@')
	buff.WriteString(srs.Domain)
	return buff.String(), nil
	//return fmt.Sprintf("SRS1=%s=%s==%s=%s=%s=%s@%s", hash, hostname, parts[1], parts[2], parts[3], parts[4], srs.Domain), nil
}

// Reverse the SRS email address to regular email addresss or error
func (srs *SRS) Reverse(email string) (string, error) {

	srs.setDefaults()

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
	if srs.defaultsChecked {
		return
	}

	if srs.HashLength == 0 {
		srs.HashLength = 4
	}

	switch srs.FirstSeparator {
	case '=', '+', '-':
	default:
		srs.FirstSeparator = '='
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
	maxAge        = 21
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

	if now <= then+maxAge {
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
