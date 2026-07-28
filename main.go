package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var rootServers = []string{
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

type RecordData map[string]string

type Results struct {
	CNAME []RecordData
	A     []RecordData
	AAAA  []RecordData
	MX    []RecordData
}

var simpleCache = make(map[string]Results)
var sophisCache = make(map[string]map[string]*dns.Msg)

func collectResults(name string) Results {
	if res, ok := simpleCache[name]; ok {
		return res
	}

	fullResponse := Results{}
	targetName := dns.Fqdn(name)

	response := lookup(targetName, dns.TypeCNAME)
	if response != nil {
		for _, answer := range response.Answer {
			if cname, ok := answer.(*dns.CNAME); ok {
				targetName = dns.Fqdn(cname.Target)
				fullResponse.CNAME = append(fullResponse.CNAME, RecordData{
					"name":  strings.TrimSuffix(targetName, "."),
					"alias": strings.TrimSuffix(name, "."),
				})
			}
		}
	}

	response = lookup(targetName, dns.TypeA)
	if response != nil {
		for _, answer := range response.Answer {
			if a, ok := answer.(*dns.A); ok {
				fullResponse.A = append(fullResponse.A, RecordData{
					"name":    strings.TrimSuffix(a.Header().Name, "."),
					"address": a.A.String(),
				})
			}
		}
	}

	response = lookup(targetName, dns.TypeAAAA)
	if response != nil {
		for _, answer := range response.Answer {
			if aaaa, ok := answer.(*dns.AAAA); ok {
				fullResponse.AAAA = append(fullResponse.AAAA, RecordData{
					"name":    strings.TrimSuffix(aaaa.Header().Name, "."),
					"address": aaaa.AAAA.String(),
				})
			}
		}
	}

	// --- lookup MX ---
	response = lookup(targetName, dns.TypeMX)
	if response != nil {
		for _, answer := range response.Answer {
			if mx, ok := answer.(*dns.MX); ok {
				fullResponse.MX = append(fullResponse.MX, RecordData{
					"name":       strings.TrimSuffix(mx.Header().Name, "."),
					"preference": fmt.Sprintf("%d", mx.Preference),
					"exchange":   strings.TrimSuffix(mx.Mx, "."),
				})
			}
		}
	}

	simpleCache[name] = fullResponse
	return fullResponse
}

func getDomainKey(name string) string {
	split := strings.Split(name, ".")
	if len(split) >= 2 {
		return split[len(split)-2]
	}
	return name
}

// lookup uses a recursive resolver to find the relevant answer to the query.
func lookup(targetName string, qtype uint16) *dns.Msg {
	domain := getDomainKey(targetName)
	if _, ok := sophisCache[domain]; !ok {
		sophisCache[domain] = make(map[string]*dns.Msg)
	}

	for _, rServer := range rootServers {
		var response *dns.Msg

		if cachedResp, exists := sophisCache[domain][rServer]; exists {
			response = cachedResp
		} else {
			response = queryServer(targetName, qtype, rServer)
			sophisCache[domain][rServer] = response
		}

		if response != nil {
			if len(response.Answer) > 0 {
				return response
			} else if len(response.Extra) > 0 {
				for _, additional := range response.Extra {
					if a, ok := additional.(*dns.A); ok {
						newResponse := lookupRecursive(targetName, qtype, a.A.String())
						if newResponse != nil {
							return newResponse
						}
					}
				}
			}
		}
	}
	return nil
}

// queryServer makes a UDP query to a given ip address, takes care of exceptions
func queryServer(targetName string, qtype uint16, ipAddr string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(targetName, qtype)

	client := new(dns.Client)
	client.Timeout = 3 * time.Second

	// Address must be in format IP:PORT
	response, _, err := client.Exchange(msg, ipAddr+":53")
	if err != nil {
		return nil
	}
	return response
}

// lookupRecursive starts from TLD and goes to the lowest level
func lookupRecursive(targetName string, qtype uint16, ipAddr string) *dns.Msg {
	response := queryServer(targetName, qtype, ipAddr)
	if response != nil {
		if len(response.Answer) > 0 {
			for _, answer := range response.Answer {
				// if we get a CNAME but didn't ask for a CNAME, resolve the CNAME recursively
				if answer.Header().Rrtype == dns.TypeCNAME && qtype != dns.TypeCNAME {
					if cname, ok := answer.(*dns.CNAME); ok {
						return lookup(cname.Target, qtype)
					}
				}
			}
			return response
		} else if len(response.Extra) > 0 {
			for _, additional := range response.Extra {
				if a, ok := additional.(*dns.A); ok {
					newResponse := lookupRecursive(targetName, qtype, a.A.String())
					if newResponse != nil {
						return newResponse
					}
				}
			}
		}
	}
	return response
}

func printResults(results Results) {
	for _, res := range results.CNAME {
		fmt.Printf("%s is an alias for %s\n", res["alias"], res["name"])
	}
	for _, res := range results.A {
		fmt.Printf("%s has address %s\n", res["name"], res["address"])
	}
	for _, res := range results.AAAA {
		fmt.Printf("%s has IPv6 address %s\n", res["name"], res["address"])
	}
	for _, res := range results.MX {
		fmt.Printf("%s mail is handled by %s %s\n", res["name"], res["preference"], res["exchange"])
	}
}

func main() {
	verbose := flag.Bool("v", false, "increase output verbosity")
	flag.BoolVar(verbose, "verbose", false, "increase output verbosity")

	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Println("Usage: go run resolve.go [-v] domain [domain ...]")
		return
	}

	for _, domainName := range args {
		result := collectResults(domainName)
		printResults(result)
	}
}