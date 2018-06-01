# SRS Sender Rewriting Scheme Go/Golang package

Sender Rewriting Scheme is a scheme that allows mail transfer agents (MTA) to remail/forward email message without breakig SPF (Sender Permitted Form) check.

SRS will rewrite email address something like this:

```
milos@mailspot.com  -> SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com
```

SRS address contains timestamp and hash signature so only the forwarding domain will be able to reverse the SRS address on bounce and check the integrity.

Here you can find more info on SRS in general and how it works:

- https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme
- http://www.libsrs2.org/srs/srs.pdf


*STIL UNDER DEVELOPMENT, NOT PRODUCTION READY YET!
STIL NEEDS SRS1 AND TESTING!*


## Installation <a id="installation"></a>
```
go get github.com/mileusna/srs
```

## Example<a id="example"></a>

```go
    func main() {
        // setting up engine with mandatory params
        srs := srs.SRS{
            Secret: []byte("YourSecretKeyForHashingUniqueAndPermanentPerServer"), 
            Domain: "forwarding-domain.com",
        }
        
        // forwarding
        // this code will produce something like this for fwd address
        // SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com        
        fwd, err := srs.Forward("milos@mailspot.com")
        if err != nil {
            log.Error(err)
            return
        }

        // reverse check when emails are bounced back to forwarding server
        rvs, err := srs.Reverse("SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com")
        if err != nil {
            // email is not SRS, invalid hash, invalid timestamp, timestamp out of date, etc..
            log.Error(err)
            return
        }
    }
```

