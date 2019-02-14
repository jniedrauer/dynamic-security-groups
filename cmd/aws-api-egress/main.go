package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/jniedrauer/dynamic-security-groups/pkg/awshelpers"
	"github.com/jniedrauer/dynamic-security-groups/pkg/rule"
)

// IPRangesFile is a file published by Amazon with a list of their public
// CIDRs. This file may change periodically.
const IPRangesFile = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// Rule configuration constants for AWS APIs.
const (
	httpPort     = 80
	httpsPort    = 443
	ruleProtocol = rule.ProtocolTCP
)

var ec2Client = ec2.New(session.New())

// Event is passed into the lambda function at runtime.
type Event struct {
	// Services are AWS services to whitelist.
	// See  https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
	// for a complete list of services.
	Services []string `json:"services"`

	// SecurityGroups are the security groups to apply them to.
	SecurityGroups []string `json:"securityGroups"`
}

// IPRanges is the deserialized IPRangesFile.
type IPRanges struct {
	SyncToken  string   `json:"syncToken"`
	CreateDate string   `json:"createDate"`
	Prefixes   []Prefix `json:"prefixes"`
	// IPv6 prefixes intentionally not deserialized.
}

// Prefix is a single AWS service CIDR.
type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

func main() {
	lambda.Start(lambdaHandler)
}

func lambdaHandler(_ context.Context, evt Event) (string, error) {
	return awshelpers.LambdaOutput(nil)
}
