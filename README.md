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

        // rvs is normal email address
        fmt.Println(rvs)
    }
```

## Testing

Since SRS contains timestamp component it is difficult to test package against static expected results because SRS result will change over time.
That is the reasons why the tests actually connects to most popular SRS daemon for Postfix, [postsrsd](https://github.com/roehling/postsrsd), and checks the results. As long as you use the same domain name and same secret key, results should match.

### Prerequisits
- Install postsrsd from https://github.com/roehling/postsrsd or use repo
for your linux distribution (CentOS https://wiki.mailserver.guru/doku.php/centos:mailserver.guru)
- Use the same domain and secret key in srs_test.go as postsrsd. Postsrsd key is located in
/etc/postsrsd.secret
- Run tests


