package awsips

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPRangesGetter(t *testing.T) {
	tests := []struct {
		name    string
		regions []string
		service string
		status  int
		expect  []string
		err     bool
	}{
		{
			name:    "S3USEast1",
			status:  http.StatusOK,
			regions: []string{"us-east-1"},
			service: "S3",
			expect: []string{
				"54.231.0.0/17",
				"52.92.16.0/20",
				"52.216.0.0/15",
			},
		},
		{
			name:    "S3USEast1UsWest2",
			status:  http.StatusOK,
			regions: []string{"us-east-1", "us-west-2"},
			service: "S3",
			expect: []string{
				"52.218.128.0/17",
				"54.231.0.0/17",
				"52.92.16.0/20",
				"52.92.32.0/22",
				"54.231.160.0/19",
				"52.216.0.0/15",
			},
		},
		{
			name:    "AllServicesUsWest2",
			status:  http.StatusOK,
			regions: []string{"us-west-2"},
			service: "AMAZON",
			expect: []string{
				"52.93.20.17/32",
				"52.95.40.0/24",
				"52.93.12.12/32",
				"52.218.128.0/17",
				"54.240.230.0/23",
				"54.239.0.32/28",
				"52.93.20.16/32",
				"54.239.2.0/23",
				"52.94.120.0/22",
				"205.251.232.0/22",
				"52.144.194.64/26",
				"52.94.208.0/21",
				"52.94.197.0/24",
				"52.93.14.19/32",
				"52.94.28.0/23",
				"54.240.248.0/21",
				"54.239.48.0/22",
				"52.93.14.18/32",
				"52.144.197.192/26",
				"52.144.197.128/26",
				"52.119.252.0/22",
				"52.92.32.0/22",
				"52.144.194.128/26",
				"54.231.160.0/19",
				"52.46.216.0/22",
				"52.94.76.0/22",
				"52.119.160.0/20",
				"52.93.12.13/32",
				"176.32.125.0/25",
				"52.94.10.0/24",
				"34.223.24.0/22",
			},
		},
		{
			name:    "ServerError",
			status:  http.StatusBadGateway,
			regions: []string{"us-east-1"},
			service: "S3",
			err:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.status == http.StatusOK {
					http.ServeFile(w, r, "testdata/ip-ranges.json")
					return
				}

				http.Error(w, "you broke the internet", test.status)
			}))
			defer ts.Close()

			getter := NewIPRangesGetter(ts.URL, test.regions)
			result, err := getter.GetService(test.service)

			if test.err {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, test.expect, result)
		})
	}
}
