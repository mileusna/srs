package srs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"math"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	ErrNoUserInSRS0           = errors.New("no user in SRS0 address")
	ErrNoUserInSRS1           = errors.New("no user in SRS1 address")
	ErrHashInvalid            = errors.New("hash invalid in SRS address")
	ErrHashTooShort           = errors.New("hash too short in SRS address")
	ErrTimestampWrongSlot     = errors.New("timestamp out of date")
	ErrTimestampInvalidBase32 = errors.New("bad base32 character in timestamp")
	ErrNoSRS                  = errors.New("not an SRS address")
	ErrNoAtSign               = errors.New("no at sign in sender address")
)

const (
	hashLength    = 4
	sep           = "="
	timePrecision = float64(60 * 60 * 24)
	timeSlots     = float64(1024) // don't make mistakes like 2 ^ 10, since in go ^ is not power operator
	maxAge        = 21
)

// SRS engine
type SRS struct {
	// Secret key, mandatory
	Secret []byte
	// Domain is localhost which will forward the emails
	Domain string
	// FirstSeparator after SRS0, optional, can be =+-, default is =
	FirstSeparator string
	// NowFunc gets called when the current time is needed.
	// Use this to time travel – e.g. for unit tests.
	// If set to nil (the default) then [time.Now] gets used.
	NowFunc func() time.Time

	once sync.Once
}

// Forward returns SRS forward address or error
func (srs *SRS) Forward(email string) (string, error) {
	srs.once.Do(srs.setDefaults)

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

	if len(local) < 5 {
		return srs.rewrite(local, hostname)
	}

	switch strings.ToUpper(local[:5]) {
	case "SRS0=", "SRS0+", "SRS0-":
		return srs.rewriteSRS0(local, hostname)

	case "SRS1=", "SRS1+", "SRS1-":
		return srs.rewriteSRS1(local, hostname)

	default:
		return srs.rewrite(local, hostname)
	}
}

// rewrite email address
func (srs *SRS) rewrite(local, hostname string) (string, error) {
	ts := base32Encode(timestamp(srs.NowFunc()))
	return "SRS0" + srs.FirstSeparator + srs.hash([]byte(strings.ToLower(ts+hostname+local))) + sep + ts + sep + hostname + sep + local + "@" + srs.Domain, nil
}

// rewriteSRS0 rewrites foreign SRS0 address to SRS1
func (srs *SRS) rewriteSRS0(local, hostname string) (string, error) {
	// Spec says:
	// SRS0 addresses have the form:
	//
	//	SRS0=opaque-part@domain-part
	//
	// where opaque-part may be defined by the SRS0 forwarder, and may only be interpreted by this same
	// host. By default, the Guarded mechanism of the Mail::SRS distribution implements this as:
	//
	//	SRS0=HHH=TT=orig-domain=orig-local-part@domain-part
	//
	// where HHH is a cryptographic hash and TT is a timestamp. The Database mechanism of the Mail::SRS
	// distribution implements SRS0 as:
	//
	//	SRS0=key@domain-part
	//
	// where key is a database primary key used for retrieving SRS-related information.
	// Other implementations are possible.
	hash := srs.hash([]byte(strings.ToLower(hostname + local[4:])))
	return "SRS1" + srs.FirstSeparator + hash + sep + hostname + sep + string(local[4]) + local[5:] + "@" + srs.Domain, nil
}

// rewriteSRS1 rewrites foreign SRS1 address to new SRS1
func (srs *SRS) rewriteSRS1(local, hostname string) (string, error) {
	// Spec says:
	// SRS1 addresses have the form:
	//
	//	SRS1=HHH=orig-local-part==HHH=TT=orig-domain-part=orig-local-part@domain-part
	//
	// where HHH is a cryptographic hash, which may be locally defined, since no other host may interpret
	// it. The double == separator is introduced since the first = is the SRS separator, and the second = is the
	// custom separator introduced by the SRS0 host and might alternatively be + or -. This double separator
	// might therefore appear as =+ or =-.
	// The SRS1 format is rigidly defined by comparison to the SRS0 format and must be adhered to, since
	// SRS1 addresses must be interpreted by remote hosts under separate administrative control.
	//
	// We actually do not need to parse all this to create our SRS1 address of another SRS1 address.
	parts := strings.SplitN(local[5:], sep, 3)
	if len(parts) != 3 {
		return "", ErrNoSRS
	}
	srsHost, srsLocal := parts[1], parts[2]

	hash := srs.hash([]byte(strings.ToLower(srsHost + srsLocal)))
	return "SRS1" + srs.FirstSeparator + hash + sep + srsHost + sep + srsLocal + "@" + srs.Domain, nil
}

// parseSRS0 local part and return hash, ts, host and local
func (srs *SRS) parseSRS0(local string) (srsLocal, srsHash, srsTimestamp, srsHost, srsUser string, err error) {
	parts := strings.SplitN(local[5:], sep, 4)
	if len(parts) < 4 {
		return "", "", "", "", "", ErrNoUserInSRS0
	}
	return local[4:], parts[0], parts[1], parts[2], parts[3], nil
}

// parseSRS1 local part and return hash, ts, host and local
func (srs *SRS) parseSRS1(local string) (srsLocal, srs1Hash, srs1Host, srsHash, srsTimestamp, srsHost, srsUser string, err error) {
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
		return "", "", "", "", "", "", "", ErrNoUserInSRS1
	}

	if len(srs1First) <= 8 {
		return "", "", "", "", "", "", "", ErrHashTooShort
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

// Reverse the SRS email address to regular email address or error
func (srs *SRS) Reverse(email string) (string, error) {
	srs.once.Do(srs.setDefaults)

	local, _, err := parseEmail(email)
	if err != nil {
		return "", ErrNoSRS
	}

	if len(local) < 5 {
		return "", ErrNoSRS
	}

	switch strings.ToUpper(local[:5]) {
	case "SRS0=", "SRS0+", "SRS0-":
		_, srsHash, srsTimestamp, srsHost, srsUser, err := srs.parseSRS0(local)
		if err != nil {
			return "", err
		}

		if err := srs.checkTimestamp(srsTimestamp); err != nil {
			return "", err
		}

		if !strings.EqualFold(srsHash, srs.hash([]byte(strings.ToLower(srsTimestamp+srsHost+srsUser)))) {
			return "", ErrHashInvalid
		}

		return srsUser + "@" + srsHost, nil

	case "SRS1=", "SRS1+", "SRS1-":
		srsLocal, srs1Hash, srs1Host, _, _, _, _, err := srs.parseSRS1(local)
		if err != nil {
			return "", err
		}

		if !strings.EqualFold(srs1Hash, srs.hash([]byte(strings.ToLower(srs1Host+srsLocal)))) {
			return "", ErrHashInvalid
		}

		return "SRS0" + srsLocal + "@" + srs1Host, nil

	default:
		return "", ErrNoSRS
	}
}

func (srs *SRS) hash(input []byte) string {
	mac := hmac.New(sha1.New, srs.Secret)
	mac.Write(input)
	s := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return s[:hashLength]
}

// setDefaults parameters if not set
func (srs *SRS) setDefaults() {
	switch srs.FirstSeparator {
	case "=", "+", "-":
	default:
		srs.FirstSeparator = "="
	}
	if srs.NowFunc == nil {
		srs.NowFunc = time.Now
	}
}

// parseEmail and return username and domain name
func parseEmail(e string) (user, domain string, err error) {
	if !strings.ContainsRune(e, '@') {
		return "", "", ErrNoAtSign // compatibility with postsrsd error message
	}

	addr, err := mail.ParseAddress(e)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", "", ErrNoAtSign

	}
	return parts[0], parts[1], nil
}

// timestamp integer
func timestamp(now time.Time) int {
	t := float64(now.Unix())
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
			return ErrTimestampInvalidBase32
		}
		then = then<<5 | pos
	}

	now := timestamp(srs.NowFunc())

	// mind the cycle of time slots
	for now < then {
		now = now + int(timeSlots)
	}

	if now <= then+maxAge {
		return nil
	}

	return ErrTimestampWrongSlot
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
