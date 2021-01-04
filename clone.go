package sip

import "net/url"

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}

// cloneOrMakeHeader invokes Header.Clone but if the
// result is nil, it'll instead make and return a non-nil Header.
func cloneOrMakeHeader(hdr Header) Header {
	clone := hdr.Clone()
	if clone == nil {
		clone = make(Header)
	}
	return clone
}
