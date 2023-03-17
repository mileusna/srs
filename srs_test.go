package srs

import (
	"strings"
	"testing"
	"time"
)

var as = strings.Repeat("a", 512-9)

func TestSRS_Forward(t *testing.T) {
	// configuration the same as in PostSRS blackbox test
	var srs = SRS{
		Secret:         []byte("tops3cr3t"),
		Domain:         "example.com",
		FirstSeparator: "=",
		NowFunc: func() time.Time {
			return time.Date(2020, time.January, 1, 0, 1, 0, 0, time.UTC)
		},
	}
	tests := []struct {
		name    string
		email   string
		want    string
		wantErr bool
	}{
		{"Need not rewrite local domain", "test@example.com", "test@example.com", false},
		{"Regular rewrite", "test@otherdomain.com", "SRS0=vmyz=2W=otherdomain.com=test@example.com", false},
		{"No rewrite for mail address without domain", "foo", "", true},
		{"Test empty address", "", "", true},
		{"Convert foreign SRS0 address to SRS1 address", "SRS0=opaque+string@otherdomain.com", "SRS1=chaI=otherdomain.com==opaque+string@example.com", false},
		{"Change domain part of foreign SRS1 address", "SRS1=X=thirddomain.com==opaque+string@otherdomain.com", "SRS1=JIBX=thirddomain.com==opaque+string@example.com", false},
		{"Test long address", "test@" + as + ".net", "SRS0=G7tR=2W=" + as + ".net=test@example.com", false},
		// TODO: {"Test too long address", "test@" + as + "a.net", "", true},
		{"Special case of local domain (is this ok?)", "test@", "SRS0=RrXq=2W==test@example.com", false},
		{"Regular rewrite longer address", "testing@otherdomain.com", "SRS0=rNNq=2W=otherdomain.com=testing@example.com", false},
		{"Invalid SRS1", "SRS1=X=thirddomain.com@otherdomain.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := srs.Forward(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("srs.Forward() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("srs.Forward() = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestSRS_Reverse(t *testing.T) {
	// configuration the same as in PostSRS blackbox test
	var srs = SRS{
		Secret:         []byte("tops3cr3t"),
		Domain:         "example.com",
		FirstSeparator: "=",
		NowFunc: func() time.Time {
			return time.Date(2020, time.January, 1, 0, 1, 0, 0, time.UTC)
		},
	}
	tests := []struct {
		name    string
		email   string
		want    string
		wantErr bool
	}{
		{"Recover original mail address from valid SRS0 address", "SRS0=XjO9=2V=otherdomain.com=test@example.com", "test@otherdomain.com", false},
		{"Recover original SRS0 address from valid SRS1 address", "SRS1=JIBX=thirddomain.com==opaque+string@example.com", "SRS0=opaque+string@thirddomain.com", false},
		{"Do not rewrite mail address which is not an SRS address", "test@example.com", "", true},
		{"Reject valid SRS0 address with time stamp older than 6 months", "SRS0=te87=T7=otherdomain.com=test@example.com", "", true},
		{"Reject valid SRS0 address with time stamp 6 month in the future", "SRS0=VcIb=7N=otherdomain.com=test@example.com", "", true},
		{"Reject SRS0 address with invalid hash", "SRS0=FAKE=2V=otherdomain.com=test@example.com", "", true},
		{"Recover mail address from all-lowercase SRS0 address", "srs0=xjo9=2v=otherdomain.com=test@example.com", "test@otherdomain.com", false},
		{"Recover mail address from all-uppcase SRS0 address", "SRS0=XJO9=2V=OTHERDOMAIN.COM=TEST@EXAMPLE.COM", "TEST@OTHERDOMAIN.COM", false},
		{"Reject SRS0 address without authenticating hash", "SRS0=@example.com", "", true},
		{"Reject SRS0 address without time stamp", "SRS0=XjO9@example.com", "", true},
		{"Reject SRS0 address without original domain", "SRS0=XjO9=2V@example.com", "", true},
		{"Reject SRS0 address without original localpart", "SRS0=XjO9=2V=otherdomain.com@example.com", "", true},
		// TODO: {"Reject Database alias", "SRS0=bxzH=2W=1=DCJGDE6N24LCRT41A4T0G1UIF0DTKKQJ@example.com", "", true},
		{"Recover long address", "SRS0=G7tR=2W=" + as + ".net=test@example.com", "test@" + as + ".net", false},
		{"Empty", "", "", true},
		{"No email", "some random string", "", true},
		{"No SRS", "something@localhost", "", true},
		{"Bogus SRS1", "SRS1-@example.com", "", true},
		{"Reject wrong hash of SRS1", "SRS1=XXXX=thirddomain.com==opaque+string@example.com", "", true},
		{"Reject wrong timestamp of SRS0", "SRS0=XjO9=00=otherdomain.com=test@example.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := srs.Reverse(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("srs.Forward() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("srs.Forward() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSRS_setDefaults(t *testing.T) {
	s := SRS{}
	s.setDefaults()
	if s.FirstSeparator != "=" {
		t.Errorf("s.FistSeparator = %q, want %q", s.FirstSeparator, "=")
	}
	if s.NowFunc == nil {
		t.Errorf("s.NowFunc = nil, want time.Now")
	}
}

func Test_parseEmail(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantUser   string
		wantDomain string
		wantErr    bool
	}{
		{"no @", "no-at", "", "", true},
		{"mail.ParseAddress error", "(test@domain", "", "", true},
		{"works", "test@domain", "test", "domain", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotDomain, err := parseEmail(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUser != tt.wantUser {
				t.Errorf("parseEmail() gotUser = %v, want %v", gotUser, tt.wantUser)
			}
			if gotDomain != tt.wantDomain {
				t.Errorf("parseEmail() gotDomain = %v, want %v", gotDomain, tt.wantDomain)
			}
		})
	}
}
