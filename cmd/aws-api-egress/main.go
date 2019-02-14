package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/jniedrauer/dynamic-security-groups/pkg/awshelpers"
	"github.com/jniedrauer/dynamic-security-groups/pkg/awsips"
	"github.com/jniedrauer/dynamic-security-groups/pkg/rule"
)

// Rule configuration constants for AWS APIs.
const (
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

	// Regions are the regions to whitelist.
	Regions []string `json:"regions"`

	// SecurityGroups are the security groups to apply them to.
	SecurityGroups []string `json:"securityGroups"`
}

// Service is an AWS service.
type Service struct {
	Name  string
	CIDRs []string
}

func main() {
	lambda.Start(lambdaHandler)
}

func lambdaHandler(_ context.Context, evt Event) (string, error) {
	getter := awsips.NewIPRangesGetter(awsips.IPRangesFile, evt.Regions)

	services := make([]Service, 0)

	for _, svc := range evt.Services {
		cidrs, err := getter.GetService(svc)
		if err != nil {
			log.Printf("Failed to read CIDRs for service %s: %+v", svc, err)
			return awshelpers.LambdaOutput(err)
		}

		services = append(services, Service{
			Name:  svc,
			CIDRs: cidrs,
		})
	}

	rules := make([]rule.Rule, len(services))
	for i := range services {
		rules[i] = rule.Rule{
			Name:     services[i].Name,
			Port:     httpsPort,
			Protocol: rule.ProtocolTCP,
			Egress:   true,
			CIDRs:    services[i].CIDRs,
		}
	}

	errs := make([]error, 0)
	for _, sgid := range evt.SecurityGroups {
		sg, err := awshelpers.DescribeSecurityGroup(sgid, ec2Client)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if err := rule.Add(rules, sg, ec2Client); err != nil {
			log.Printf("Failed to add rules: %+v", err)
			errs = append(errs, err)
		}

		if err := rule.Cleanup(rules, sg, ec2Client); err != nil {
			log.Printf("Failed to clean up rules: %+v", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return awshelpers.LambdaOutput(errs[0])
	}

	return awshelpers.LambdaOutput(nil)
}
