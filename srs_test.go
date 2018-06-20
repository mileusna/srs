package srs_test

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/mileusna/srs"
)

// Since SRS contains timestamp component, it is difficult to test package
// against static expected results because SRS result change over time.
// That is the reasons why this tests acutally connects to most populpar SRS
// daemon for Postfix, postsrsd, and checks the results. As long as you use the
// same domain name and same secret key, results have to match.

// Prerequisits:
// Install postsrsd from https://github.com/roehling/postsrsd or use repo
// for your linux distribution (CentOS https://wiki.mailserver.guru/doku.php/centos:mailserver.guru)
// Use the same domain and secret key as postsrsd.
// Postsrsd config is /etc/sysconfig/postsrsd
// Postsrsd key is in /etc/postsrsd.secret
// Run tests

// Params should be the same as in /etc/sysconfig/postsrsd and secret from /etc/postsrsd.secret
const (
	localdomain = "localhost.localdomain"
	secret      = "9/sg9mSnEHHvH4giEP/NzRwY"
	firstSep    = "="
)

var srsCli = srs.SRS{
	Secret:         []byte(secret),
	Domain:         localdomain,
	FirstSeparator: firstSep,
}

// test base, this contains good and bad emails and SRS0/SRS1 emails
// Additionald SRS0/SRS1 email addresses will be generated from this list for testing purpouse
var testBase = []string{
	"milos@mailspot.com",
	"milos@NASLOVI.NET",  // uppercase
	"Milos@MailSpot.com", // mixed case
	"milos@localhost.localdomain",
	"myemail@domain.com",
	"myemail@domain.co.uk",
	"myemail@domain.co.uk",
	"milos.mileusnic@domain.co.uk",
	"milosmileusnic@domain",
	"hello+world@domain.com",
	"asdijaoisjd asidj oaisjd",
	"SRS0=8Zzm=IS=netmark.rs=milos@domain.com",
	"SRS0=8Zzm=IC=netmark.rs=milos@domain.com",
	"SRS0=8ZzmIS=netmark.rs=milos@" + localdomain,
	"SRS0=8ZzmIS=netmark.rs=milos@" + localdomain,
	"SRS0=8Zzm=IS=netmark.rsmilos@" + localdomain,
	"SRS0+8Zzm=IS=netmark.rs=milos@domain.com",
	"SRS0+8Zzm=IC=netmark.rs=milos@domain.com",
	"SRS0+8ZzmIS=netmark.rs=milos@" + localdomain,
	"SRS0+8ZzmIS=netmark.rs=milos@" + localdomain,
	"SRS0+8Zzm=IS=netmark.rsmilos@" + localdomain,
	"SRS0=nrAG=JF=domain.com=hello+world@" + localdomain,
	"SRS1=50B9=domain.net==8Zzm=IS=netmark.rs=milos@" + localdomain,
	"SRS1=omnM=domain.com==8Znm=IC=netmark.rs=milos@" + localdomain,
	"SRS0=8Zzm=II=netmark.rsmilos@" + localdomain,
	"SRS1=50B9=domain.net==@" + localdomain,
	"SRS1=ddd9==8Znm=IC=netmark.rs=milos@" + localdomain,
	"SRS1=8Zzm=IC=netmark.rs=milos@domain.com",
	"SRS1=wtfisthis=milos@domain.com",
	"SRS1===@domain.com",
}

// This case are valid in postsrsd but I find them wrong and they won't be supported
// I guess that postsrsd rely on postfix to reject this type of email
// addresses so it doesn't check bad email formats
// "SRS08Zcm=IS=netmark.rs=milos@", // no domain
// "milos@",                        // no domain
// "milos@netmark.rs@domain.com",   // two @ signs
// "milosmileusnic@domain,net",     // comma in domain name
// "milos mileusnic@domain.net",    // space in email

func generateEmails(srs srs.SRS) []string {

	emails := testBase

	// add SRS0 emails to test list
	var srs0Emails []string
	for _, e := range emails {
		if fwd, err := srs.Forward(e); err == nil {
			srs0Emails = append(srs0Emails, fwd)
		}
	}
	emails = append(emails, srs0Emails...)

	// add SRS1 emails to test list
	var srs1Emails []string
	for _, e := range srs0Emails {
		if fwd, err := srs.Forward(e); err == nil {
			srs1Emails = append(srs1Emails, fwd)
		}
	}
	return append(emails, srs1Emails...)
}

func TestForward(t *testing.T) {
	testEmails(t, generateEmails(srsCli), srsCli.Forward, postSRSForward)
}

func TestReverse(t *testing.T) {
	testEmails(t, generateEmails(srsCli), srsCli.Reverse, postSRSReverse)
}

func testEmails(t *testing.T, emails []string, fn func(string) (string, error), postsrsFn func(string) (int, string)) {
	for _, email := range emails {
		code := 200
		posrtsrsCode, postsrsdRes := postsrsFn(email)
		res, err := fn(email)
		if err != nil {
			res = err.Error()
			code = 500
		}

		//fmt.Println(res)

		if code != posrtsrsCode {
			fmt.Println()
			fmt.Println("email:   ", email)
			fmt.Println("postsrsd:", postsrsdRes)
			fmt.Println("go:      ", res)
			fmt.Println()
			t.Error("Codes returned don't match")
			continue
		}

		if code != 200 && code == posrtsrsCode && res != strings.TrimSuffix(postsrsdRes, ".") {
			fmt.Println()
			fmt.Println("Notice:  ", "Codes returned match but not the same error message (this is OK)")
			fmt.Println("email:   ", email)
			fmt.Println("postsrsd:", postsrsdRes)
			fmt.Println("go:      ", res)
			fmt.Println()
			continue
		}

		if code == 200 && res != postsrsdRes {
			fmt.Println()
			fmt.Println("email:   ", email)
			fmt.Println("postsrsd:", postsrsdRes)
			fmt.Println("go:      ", res)
			fmt.Println()
			t.Error("No match")
		}
	}

}

var (
	postSRSForward = postsrs("10001")
	postSRSReverse = postsrs("10002")
)

func postsrs(port string) func(email string) (code int, fwd string) {
	return func(email string) (code int, fwd string) {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		fmt.Fprintf(conn, "get %s\n", email)
		message, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		message = strings.TrimSpace(message)
		msgParts := strings.SplitN(message, " ", 2)
		if len(msgParts) < 2 {

		}
		code, _ = strconv.Atoi(msgParts[0])
		return code, msgParts[1]
	}
}
