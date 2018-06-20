package srs

import (
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

const (
	hashLength = 4
	sep        = "="
)

// SRS engine
type SRS struct {
	// Secret key, mandatory
	Secret []byte
	// Domain is localhost which will forward the emails
	Domain string
	// FirstSeparator after SRS0, optional, can be =+-, default is =
	FirstSeparator string

	defaultsChecked bool
}

// Forward returns SRS forward address or error
func (srs *SRS) Forward(email string) (string, error) {
	srs.setDefaults()

	var noDomain bool
	if strings.HasSuffix(email, "@") {
		email += srs.Domain
		noDomain = true
	}

	local, hostname, err := parseEmail(email)
	if err != nil {
		return "", err
	}
	if noDomain {
		hostname = ""
	}

	if hostname == srs.Domain {
		return email, nil
	}

	switch local[:5] {
	case "SRS0=", "SRS0+", "SRS0-":
		return srs.rewriteSRS0(local, hostname)

	case "SRS1=", "SRS1+", "SRS1-":
		return srs.rewriteSRS1(local, hostname)

	default:
		return srs.rewrite(local, hostname)
	}

}

// rewrite email address
func (srs SRS) rewrite(local, hostname string) (string, error) {
	ts := base32Encode(timestamp())
	return "SRS0" + srs.FirstSeparator + srs.hash([]byte(strings.ToLower(ts+hostname+local))) + sep + ts + sep + hostname + sep + local + "@" + srs.Domain, nil
}

// rewriteSRS0 rewrites SRS0 address to SRS1
func (srs SRS) rewriteSRS0(local, hostname string) (string, error) {
	srsLocal, srsHash, srsTimestamp, srsHost, srsUser, err := srs.parseSRS0(local)
	if err != nil {
		return "", errors.New("No user in SRS0 address")
	}
	hash := srs.hash([]byte(strings.ToLower(hostname + srsLocal)))
	return "SRS1" + srs.FirstSeparator + hash + sep + hostname + sep + string(local[4]) + srsHash + sep + srsTimestamp + sep + srsHost + sep + srsUser + "@" + srs.Domain, nil
}

// parseSRS0 local part and return hash, ts, host and local
func (srs SRS) parseSRS0(local string) (srsLocal, srsHash, srsTimestamp, srsHost, srsUser string, err error) {
	parts := strings.SplitN(local[5:], sep, 4)
	if len(parts) < 4 {
		return "", "", "", "", "", errors.New("No user in SRS0 address")
	}
	return local[4:], parts[0], parts[1], parts[2], parts[3], nil
}

// rewriteSRS1 rewrites SRS1 address to new SRS1
func (srs SRS) rewriteSRS1(local, hostname string) (string, error) {
	srsLocal, _, srs1Host, srsHash, srsTimestamp, srsHost, srsUser, err := srs.parseSRS1(local)
	if err != nil {
		return "", errors.New("No user in SRS1 address")
	}

	hash := srs.hash([]byte(strings.ToLower(srs1Host + srsLocal)))
	return "SRS1" + srs.FirstSeparator + hash + sep + srs1Host + sep + string(local[4]) + srsHash + sep + srsTimestamp + sep + srsHost + sep + srsUser + "@" + srs.Domain, nil
}

// parseSRS1 local part and return hash, ts, host and local
func (srs SRS) parseSRS1(local string) (srsLocal, srs1Hash, srs1Host, srsHash, srsTimestamp, srsHost, srsUser string, err error) {

	var srs1Sep, srs1First, srs1Second string
	for i := 0; i < len(local)-1; i++ {
		sep := local[i : i+2]
		if sep == "==" || sep == "=+" || sep == "=-" {
			srs1Sep = string(local[i+1])
			srs1First = local[0:i]
			srs1Second = local[i+2:]
			break
		}
	}

	if srs1First == "" && srs1Second == "" {
		return "", "", "", "", "", "", "", errors.New("No user in SRS1 address")
	}

	if len(srs1First) <= 8 {
		return "", "", "", "", "", "", "", errors.New("Hash too short in SRS address")
	}

	srsLocal = srs1Sep + srs1Second

	h := strings.SplitN(srs1First[5:], sep, 2)
	if len(h) == 2 {
		srs1Hash = h[0]
		srs1Host = h[1]
	}

	parts := strings.SplitN(srs1Second, sep, 4)
	if len(parts) < 4 {
		return srsLocal, srs1Hash, srs1Host, "", "", "", "", nil
	}

	return srsLocal, srs1Hash, srs1Host, parts[0], parts[1], parts[2], parts[3], nil
}

// Reverse the SRS email address to regular email addresss or error
func (srs *SRS) Reverse(email string) (string, error) {
	srs.setDefaults()

	local, _, err := parseEmail(email)
	if err != nil {
		return "", errors.New("Not an SRS address")
	}

	switch local[:5] {
	case "SRS0=", "SRS0+", "SRS0-":
		_, srsHash, srsTimestamp, srsHost, srsUser, err := srs.parseSRS0(local)
		if err != nil {
			return "", err
		}

		if err := srs.checkTimestamp(srsTimestamp); err != nil {
			return "", err
		}

		if srsHash != srs.hash([]byte(strings.ToLower(srsTimestamp+srsHost+srsUser))) {
			return "", errors.New("Hash invalid in SRS address")
		}

		return srsUser + "@" + srsHost, nil

	case "SRS1=", "SRS1+", "SRS1-":
		srsLocal, srs1Hash, srs1Host, _, _, _, _, err := srs.parseSRS1(local)
		if err != nil {
			return "", err
		}

		if srs1Hash != srs.hash([]byte(strings.ToLower(srs1Host+srsLocal))) {
			return "", errors.New("Hash invalid in SRS address")
		}

		return "SRS0" + srsLocal + "@" + srs1Host, nil

	default:
		return "", errors.New("Not an SRS address")
	}

}

func (srs SRS) hash(input []byte) string {
	mac := hmac.New(sha1.New, srs.Secret)
	mac.Write(input)
	s := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return s[:hashLength]
}

// setDefaults parameters if not set
func (srs *SRS) setDefaults() {
	if srs.defaultsChecked {
		return
	}

	switch srs.FirstSeparator {
	case "=", "+", "-":
	default:
		srs.FirstSeparator = "="
	}

	srs.defaultsChecked = true
}

// parseEmail and return username and domain name
func parseEmail(e string) (user, domain string, err error) {
	if !strings.ContainsRune(e, '@') {
		return "", "", errors.New("No at sign in sender address") // compatibility with postsrsd error message
	}

	addr, err := mail.ParseAddress(e)
	if err != nil {
		return "", "", errors.New("Bad formated email address")
	}
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", "", errors.New("No at sign in sender address")

	}
	return parts[0], parts[1], nil
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
