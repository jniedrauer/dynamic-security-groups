package rule

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/stretchr/testify/assert"
)

func TestExists(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		rule Rule
		sg   *ec2.SecurityGroup

		expect bool
	}{
		{
			name: "SingleEgressRuleExists",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   true,
			},
			sg: &ec2.SecurityGroup{
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8080),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
			},

			expect: true,
		},
		{
			name: "SingleIngressRuleExists",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   false,
			},
			sg: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8080),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
			},

			expect: true,
		},
		{
			name: "PortMismatch",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   false,
			},
			sg: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8081),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
			},

			expect: false,
		},
		{
			name: "NilPort",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   false,
			},
			sg: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{},
				},
			},

			expect: false,
		},
		{
			name: "NilProtocol",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   false,
			},
			sg: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort: aws.Int64(8080),
						ToPort:   aws.Int64(8081),
						IpRanges: []*ec2.IpRange{
							{},
						},
					},
				},
			},

			expect: false,
		},
		{
			name: "NilCIDR",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   false,
			},
			sg: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8081),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{},
						},
					},
				},
			},

			expect: false,
		},
		{
			name: "DoesNotExist",
			ip:   "123.123.123.123",
			rule: Rule{
				Port:     8080,
				Protocol: ProtocolTCP,
				Egress:   true,
			},
			sg: &ec2.SecurityGroup{
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(8081),
						ToPort:     aws.Int64(8081),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8080),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.124/32"),
							},
						},
					},
					{
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(8080),
						IpProtocol: aws.String(ProtocolUDP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
			},

			expect: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Exists(test.ip, test.rule, test.sg)
			assert.Equal(t, test.expect, result)
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name      string
		rules     []Rule
		sg        *ec2.SecurityGroup
		ec2Client *mockEC2Client

		expectErr         bool
		expectEgressCall  *ec2.AuthorizeSecurityGroupEgressInput
		expectIngressCall *ec2.AuthorizeSecurityGroupIngressInput
	}{
		{
			name: "AddSingleEgressRule",
			rules: []Rule{
				{
					Name:        "api.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.123"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
			},
			ec2Client: &mockEC2Client{},

			expectEgressCall: &ec2.AuthorizeSecurityGroupEgressInput{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "AddSingleIngressRule",
			rules: []Rule{
				{
					Name:        "api.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					IPAddresses: []string{"123.123.123.123"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
			},
			ec2Client: &mockEC2Client{},

			expectIngressCall: &ec2.AuthorizeSecurityGroupIngressInput{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "AddMultipleEgressRules",
			rules: []Rule{
				{
					Name:        "api.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.123"},
				},
				{
					Name:        "api.dev.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.124"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
			},
			ec2Client: &mockEC2Client{},

			expectEgressCall: &ec2.AuthorizeSecurityGroupEgressInput{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.124/32"),
								Description: aws.String("AUTOGENERATED: api.dev.foo.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "AddExistingRule",
			rules: []Rule{
				{
					Name:        "api.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.123"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{},
		},
		{
			name: "AddRuleError",
			rules: []Rule{
				{
					Name:        "api.foo.com",
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.123"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
			},
			ec2Client: &mockEC2Client{
				Err: errors.New("😱"),
			},

			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.ec2Client.AuthorizeSecurityGroupEgressCalls = make(chan *ec2.AuthorizeSecurityGroupEgressInput, 1)
			test.ec2Client.AuthorizeSecurityGroupIngressCalls = make(chan *ec2.AuthorizeSecurityGroupIngressInput, 1)

			err := Add(test.rules, test.sg, test.ec2Client)

			if test.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			select {
			case call := <-test.ec2Client.AuthorizeSecurityGroupEgressCalls:
				assert.EqualValues(t, test.expectEgressCall, call)
			default:
				if test.expectEgressCall != nil {
					t.Fatal("Expected egress rules to be added")
				}
			}

			select {
			case call := <-test.ec2Client.AuthorizeSecurityGroupIngressCalls:
				assert.EqualValues(t, test.expectIngressCall, call)
			default:
				if test.expectIngressCall != nil {
					t.Fatal("Expected ingress rules to be added")
				}
			}
		})
	}
}

func TestCleanup(t *testing.T) {
	tests := []struct {
		name      string
		rules     []Rule
		sg        *ec2.SecurityGroup
		ec2Client *mockEC2Client

		expectErr         bool
		expectEgressCall  *ec2.RevokeSecurityGroupEgressInput
		expectIngressCall *ec2.RevokeSecurityGroupIngressInput
	}{
		{
			name: "RevokeSingleEgressRule",
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{},

			expectEgressCall: &ec2.RevokeSecurityGroupEgressInput{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "RevokeSingleIngressRule",
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{},

			expectIngressCall: &ec2.RevokeSecurityGroupIngressInput{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
		},
		{
			name: "NoRulesToRevoke",
			rules: []Rule{
				{
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      false,
					IPAddresses: []string{"123.123.123.123"},
				},
				{
					Port:        443,
					Protocol:    ProtocolTCP,
					Egress:      true,
					IPAddresses: []string{"123.123.123.123"},
				},
			},
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{},
		},
		{
			name: "NoAutogeneratedRulesToRevoke",
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("123.123.123.123/32"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{},
		},
		{
			name: "NoRules",
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
			},
			ec2Client: &mockEC2Client{},
		},
		{
			name: "Error",
			sg: &ec2.SecurityGroup{
				GroupId: aws.String("sg-123"),
				IpPermissionsEgress: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String(ProtocolTCP),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("123.123.123.123/32"),
								Description: aws.String("AUTOGENERATED: api.foo.com"),
							},
						},
					},
				},
			},
			ec2Client: &mockEC2Client{
				Err: errors.New("👎"),
			},

			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.ec2Client.RevokeSecurityGroupEgressCalls = make(chan *ec2.RevokeSecurityGroupEgressInput, 1)
			test.ec2Client.RevokeSecurityGroupIngressCalls = make(chan *ec2.RevokeSecurityGroupIngressInput, 1)

			err := Cleanup(test.rules, test.sg, test.ec2Client)

			if test.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			select {
			case call := <-test.ec2Client.RevokeSecurityGroupEgressCalls:
				assert.EqualValues(t, test.expectEgressCall, call)
			default:
				if test.expectEgressCall != nil {
					t.Fatal("Expected egress rules to be added")
				}
			}

			select {
			case call := <-test.ec2Client.RevokeSecurityGroupIngressCalls:
				assert.EqualValues(t, test.expectIngressCall, call)
			default:
				if test.expectIngressCall != nil {
					t.Fatal("Expected ingress rules to be added")
				}
			}
		})
	}
}

type mockEC2Client struct {
	ec2iface.EC2API

	AuthorizeSecurityGroupEgressCalls  chan *ec2.AuthorizeSecurityGroupEgressInput
	AuthorizeSecurityGroupIngressCalls chan *ec2.AuthorizeSecurityGroupIngressInput

	RevokeSecurityGroupEgressCalls  chan *ec2.RevokeSecurityGroupEgressInput
	RevokeSecurityGroupIngressCalls chan *ec2.RevokeSecurityGroupIngressInput

	Err error
}

func (m *mockEC2Client) AuthorizeSecurityGroupEgress(input *ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
	m.AuthorizeSecurityGroupEgressCalls <- input
	return nil, m.Err
}

func (m *mockEC2Client) AuthorizeSecurityGroupIngress(input *ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	m.AuthorizeSecurityGroupIngressCalls <- input
	return nil, m.Err
}

func (m *mockEC2Client) RevokeSecurityGroupEgress(input *ec2.RevokeSecurityGroupEgressInput) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	m.RevokeSecurityGroupEgressCalls <- input
	return nil, m.Err
}

func (m *mockEC2Client) RevokeSecurityGroupIngress(input *ec2.RevokeSecurityGroupIngressInput) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	m.RevokeSecurityGroupIngressCalls <- input
	return nil, m.Err
}
