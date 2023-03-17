# SRS Sender Rewriting Scheme Go/Golang package

Sender Rewriting Scheme is a scheme that allows mail transfer agents (MTA) like Postfix or Exim to remail/forward email message without breakig SPF (Sender Permitted Form) check.

SRS will rewrite email address something like this:

```
milos@mailspot.com  ->  SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com
```

SRS address contains timestamp and hash signature so only the forwarding domain will be able to reverse the SRS address on bounce and check the integrity.

Here you can find more info on SRS in general and how it works:

- https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme
- http://www.libsrs2.org/srs/srs.pdf


## Installation <a id="installation"></a>
```
go get github.com/mileusna/srs
```

## Example<a id="example"></a>

```go
    func main() {
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

        // reverse check when emails are bounced back to forwarding server
        rvs, err := s.Reverse("SRS0=JvSE=IT=mailspot.com=milos@forwarding-domain.com")
        if err != nil {
            // email is not SRS, invalid hash, invalid timestamp, timestamp out of date, etc..
            log.Fatal(err)
        }

        // rvs is normal email address
        fmt.Println(rvs)
    }
```

### Exceptions

There are some cases which postsrsd will accept, but I find them wrong and they won't be supported by this package.
I guess that postsrsd rely on mail server to reject this type of email addresses so it doesn't check bad email formats. 

These are some examples which postsrsd will accept, but this go package will return an error due to bad email formatting:

- milos@ // @ sign but no domain
- milos@netmark.rs@domain.com    // two @ signs
- milosmileusnic@domain,net     // comma in domain name
- milos mileusnic@domain.net    // space in user
- etc.
