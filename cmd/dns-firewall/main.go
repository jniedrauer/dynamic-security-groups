package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/jniedrauer/dynamic-security-groups/pkg/awshelpers"
	"github.com/jniedrauer/dynamic-security-groups/pkg/rule"
)

var ec2Client = ec2.New(session.New())

// Event is passed into the lambda function at runtime.
type Event struct {
	// Rules are the rules to apply.
	Rules []rule.Rule `json:"rules"`

	// SecurityGroups are the security groups to apply them to.
	SecurityGroups []string `json:"securityGroups"`
}

func main() {
	lambda.Start(lambdaHandler)
}

func lambdaHandler(_ context.Context, evt Event) (string, error) {
	rules := make([]rule.Rule, len(evt.Rules))
	copy(rules, evt.Rules)

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
