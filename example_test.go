package srs_test

import (
	"fmt"
	"log"

	"github.com/mileusna/srs"
)

func ExampleSRS_Forward() {
	// setting up engine with mandatory params
	s := srs.SRS{
		Secret: []byte("YourSecretKeyForHashingUniqueAndPermanentPerServer"),
		Domain: "forwarding-domain.com",
	}

	// forwarding
	// this code will produce something like this for fwd address
	// SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com
	fwd, err := s.Forward("milos@mailspot.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(fwd)
}

func ExampleSRS_Reverse() {
	// setting up engine with mandatory params
	s := srs.SRS{
		Secret: []byte("YourSecretKeyForHashingUniqueAndPermanentPerServer"),
		Domain: "forwarding-domain.com",
	}

	// reverse check when emails are bounced back to forwarding server
	rvs, err := s.Reverse("SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com")
	if err != nil {
		// email is not SRS, invalid hash, invalid timestamp, timestamp out of date, etc..
		log.Fatal(err)
	}

	// rvs is normal email address
	fmt.Println(rvs)
}
