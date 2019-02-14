package awsips

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// IPRangesFile is a file published by Amazon with a list of their public
// CIDRs. This file may change periodically.
const IPRangesFile = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// blacklistedServices is used to remove services from the generated rules. The
// EC2 service is specifically blacklisted because it contains the IP space for
// public (ie. customer managed) EC2 IP addresses.
var blacklistedServices = []string{
	"EC2",
}

// IPRanges is the deserialized IPRangesFile.
type IPRanges struct {
	SyncToken  string   `json:"syncToken"`
	CreateDate string   `json:"createDate"`
	Prefixes   []Prefix `json:"prefixes"`
	// IPv6 prefixes not implemented
}

// Prefix is a single AWS service CIDR.
type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

// IPRangesGetter deserializes a remote IP rages file.
type IPRangesGetter struct {
	// url is the URL to download the IP ranges file from.
	url string

	// regions are the regions to get IP addresses in.
	regions []string

	httpClient *http.Client
	ipRanges   *IPRanges
	getOnce    sync.Once
}

// NewIPRangesGetter creates a new configured IPRangesLoader.
func NewIPRangesGetter(uri string, regions []string) *IPRangesGetter {
	return &IPRangesGetter{
		url:     uri,
		regions: regions,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get gets the latest IP ranges.
func (g *IPRangesGetter) Get() (*IPRanges, error) {
	var err error

	g.getOnce.Do(func() {
		var req *http.Request
		req, err = http.NewRequest(http.MethodGet, g.url, nil)
		if err != nil {
			return
		}

		var res *http.Response
		res, err = g.httpClient.Do(req)
		if err != nil {
			return
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			err = fmt.Errorf("Got status: %d", res.StatusCode)
			return
		}

		result := &IPRanges{}
		if err := json.NewDecoder(res.Body).Decode(result); err != nil {
			return
		}

		g.ipRanges = result
	})

	return g.ipRanges, err
}

// GetService gets a list of CIDRs for a given service. The EC2 service is
// explicitly filtered from the results, since it contains third party EC2
// instance IPs.
func (g *IPRangesGetter) GetService(service string) ([]string, error) {
	unfiltered, err := g.getUnfilteredService(service)
	if err != nil {
		return nil, err
	}

	blacklist := make([]string, 0)
	for _, svc := range blacklistedServices {
		cidrs, err := g.getUnfilteredService(svc)
		if err != nil {
			return nil, err
		}
		blacklist = append(blacklist, cidrs...)
	}

	filtered := unfiltered[:0]
	for _, val := range unfiltered {
		if !in(val, blacklist) {
			filtered = append(filtered, val)
		}
	}

	return filtered, nil
}

// getUnfilteredService returns a list of CIDRs for a given service.
func (g *IPRangesGetter) getUnfilteredService(service string) ([]string, error) {
	ranges, err := g.Get()
	if err != nil {
		return nil, err
	}

	cidrs := make([]string, 0)
	for _, prefix := range ranges.Prefixes {
		if prefix.Service != service {
			continue
		}

		if !in(prefix.Region, g.regions) {
			continue
		}

		cidrs = append(cidrs, prefix.IPPrefix)
	}

	return cidrs, nil
}

// in returns a boolean for string in slice.
func in(match string, search []string) bool {
	for _, val := range search {
		if match == val {
			return true
		}
	}
	return false
}
