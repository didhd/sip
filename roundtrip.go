package sip

// RoundTrip implements the RoundTripper interface.
//
// For higher-level SIP client support (such as handling of cookies
// and redirects), see Client type.
//
// Like the RoundTripper interface, the error types returned
// by RoundTrip are unspecified.
func (t *Transport) RoundTrip(req *Request) (*Response, error) {
	return t.roundTrip(req)
}

func (t *Transport) OneWay(req *Request) error {
	return t.oneWay(req)
}
