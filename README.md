# Dynamic Security Groups
Update security group rules dynamically using DNS or AWS service IPs.

[![CircleCI](https://circleci.com/gh/jniedrauer/dynamic-security-groups/tree/master.svg?style=shield)](https://circleci.com/gh/jniedrauer/dynamic-security-groups/tree/master)
[![Release](https://img.shields.io/github/release/jniedrauer/dynamic-security-groups/all.svg?style=shield)](https://github.com/jniedrauer/dynamic-security-groups/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/jniedrauer/dynamic-security-groups)](https://goreportcard.com/report/github.com/jniedrauer/dynamic-security-groups)
[![GoDoc](https://godoc.org/github.com/jniedrauer/dynamic-security-groups?status.svg)](https://godoc.org/github.com/jniedrauer/dynamic-security-groups)

## Use Cases
When filtering egress traffic in AWS, there are two potential challenges:

* AWS's own IP space is not static
* Many third party APIs are not static

AWS publishes a list of IPs for their services at any given time. This list
can be parsed to generate security group rules. See
https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
for details.

To create security group rules for dynamic third party APIs, DNS resolution
can be used to determine CIDRs. This does mean that Amazon's DNS servers
become a "source of truth" for firewall rules. Additionally, APIs with
particularly low TTLs or round robin DNS can present problems for this
approach.

## Example Implementation
In this example, all egress traffic is allowed to all of AWS's IP space in the
us-west-2 region, with the exception of the EC2 IP range. The EC2 IP range is
automatically filtered out of results, since this IP range includes
customer-owned EC2 instances.

    AwsServicesFirewallFunction:
      Type: AWS::Serverless::Function
      Properties:
        Runtime: go1.x
        Timeout: 15
        CodeUri: dynamic-security-groups/aws-api-egress
        Events:
          AwsServicesFirewallTrigger:
            Properties:
              Input:
                Fn::Sub:
                  - '{"services": ["AMAZON"], "regions": ["us-west-2"], "securityGroups":
                    ["${SecurityGroup}"]}'
                  - SecurityGroup:
                      Ref: AwsServicesEgressSg
              Schedule: rate(1 hour)
            Type: Schedule
        Handler: aws-api-egress
        Policies:
          - Statement:
              - Action:
                  - ec2:DescribeSecurityGroups
                Effect: Allow
                Resource:
                  - '*'
              - Action:
                  - ec2:RevokeSecurityGroupIngress
                  - ec2:AuthorizeSecurityGroupEgress
                  - ec2:AuthorizeSecurityGroupIngress
                  - ec2:RevokeSecurityGroupEgress
                Effect: Allow
                Resource:
                  - Fn::Sub:
                      - arn:aws:ec2:*:*:security-group/${SecurityGroup}
                      - SecurityGroup:
                          Ref: AwsServicesEgressSg

In this example, egress traffic is allowed to the sendgrid REST API.

    DnsResolverFunction:
      Type: AWS::Serverless::Function
      Properties:
        Runtime: go1.x
        Timeout: 15
        CodeUri: dynamic-security-groups/dns-firewall
        Events:
          DnsResolverTrigger:
            Properties:
              Input:
                Fn::Sub:
                  - '{"rules": [{"name": "api.sendgrid.com", "port": 443, "protocol":
                    "tcp", "egress": true}], "securityGroups": ["${SecurityGroup}"]}'
                  - SecurityGroup:
                      Ref: ThirdPartyEgressSg
              Schedule: rate(5 minutes)
            Type: Schedule
        Handler: dns-firewall
        Policies:
          - Statement:
              - Action:
                  - ec2:DescribeSecurityGroups
                Effect: Allow
                Resource:
                  - '*'
              - Action:
                  - ec2:RevokeSecurityGroupIngress
                  - ec2:AuthorizeSecurityGroupEgress
                  - ec2:AuthorizeSecurityGroupIngress
                  - ec2:RevokeSecurityGroupEgress
                Effect: Allow
                Resource:
                  - Fn::Sub:
                      - arn:aws:ec2:*:*:security-group/${SecurityGroup}
                      - SecurityGroup:
                          Ref: ThirdPartyEgressSg
