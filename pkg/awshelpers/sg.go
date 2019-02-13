package awshelpers

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

// DescribeSecurityGroup describes a single security group.
func DescribeSecurityGroup(sgid string, ec2Client ec2iface.EC2API) (*ec2.SecurityGroup, error) {
	res, err := ec2Client.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(sgid),
		},
	})
	if err != nil {
		return nil, err
	}

	if len(res.SecurityGroups) != 1 {
		return nil, fmt.Errorf("unexpected number of security groups: %d", len(res.SecurityGroups))
	}

	return res.SecurityGroups[0], nil
}
