package awshelpers

// success is returned when the function succeeds.
const success = "ok"

// failure is returned when the function fails.
const failure = "failed"

// LambdaOutput standardizes lambda output format.
func LambdaOutput(err error) (string, error) {
	if err != nil {
		return failure, err
	}

	return success, nil
}
