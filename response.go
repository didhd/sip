package sip

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/textproto"
	"strconv"
	"strings"
)

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

var respExcludeHeader = map[string]bool{
	"Content-Length": true,
}

// Response represents the response from an SIP request.
//
// The Client and Transport return Responses from servers once
// the response headers have been received. The response body
// is streamed on demand as the Body field is read.
type Response struct {
	Status     string // e.g. "200 OK"
	StatusCode int    // e.g. 200
	Proto      string // e.g. "SIP/2.0"
	ProtoMajor int    // e.g. 2
	ProtoMinor int    // e.g. 0

	// Header maps header keys to values. If the response had multiple
	// headers with the same key, they may be concatenated, with comma
	// delimiters.
	//
	// Keys in the map are canonicalized (see CanonicalHeaderKey).
	Header Header

	// Body represents the response body.
	//
	// The response body is streamed on demand as the Body field
	// is read. If the network connection fails or the server
	// terminates the response, Body.Read calls return an error.
	Body io.ReadCloser

	// ContentLength records the length of the associated content. The
	// value -1 indicates that the length is unknown.
	ContentLength int64

	// Contains transfer encodings from outer-most to inner-most. Value is
	// nil, means that "identity" encoding is used.
	TransferEncoding []string

	// Close records whether the header directed that the connection be
	// closed after reading Body. The value is advice for clients: neither
	// ReadResponse nor Response.Write ever closes a connection.
	Close bool

	// Uncompressed reports whether the response was sent compressed but
	// was decompressed by the http package. When true, reading from
	// Body yields the uncompressed content instead of the compressed
	// content actually set from the server, ContentLength is set to -1,
	// and the "Content-Length" and "Content-Encoding" fields are deleted
	// from the responseHeader. To get the original response from
	// the server, set Transport.DisableCompression to true.
	Uncompressed bool

	// Trailer maps trailer keys to values in the same
	// format as Header.
	//
	// The Trailer initially contains only nil values, one for
	// each key specified in the server's "Trailer" header
	// value. Those values are not added to Header.
	//
	// Trailer must not be accessed concurrently with Read calls
	// on the Body.
	//
	// After Body.Read has returned io.EOF, Trailer will contain
	// any trailer values sent by the server.
	Trailer Header

	// Request is the request that was sent to obtain this Response.
	// Request's Body is nil (having already been consumed).
	// This is only populated for Client requests.
	Request *Request

	// TLS contains information about the TLS connection on which the
	// response was received. It is nil for unencrypted responses.
	// The pointer is shared between responses and should not be
	// modified.
	TLS *tls.ConnectionState
}

// ReadResponse reads and returns an SIP response from r.
// The req parameter optionally specifies the Request that corresponds
// to this Response. If nil, a INVITE request is assumed.
// Clients must call resp.Body.Close when finished reading resp.Body.
// After that call, clients can inspect resp.Trailer to find key/value
// pairs included in the response trailer.
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error) {
	tp := textproto.NewReader(r)
	resp := &Response{
		Request: req,
	}

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, &badStringError{"malformed SIP response", line}
	} else {
		resp.Proto = line[:i]
		resp.Status = strings.TrimLeft(line[i+1:], " ")
	}
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, &badStringError{"malformed SIP status code", statusCode}
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, &badStringError{"malformed SIP status code", statusCode}
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = ParseSIPVersion(resp.Proto); !ok {
		return nil, &badStringError{"malformed SIP version", resp.Proto}
	}

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)

	fixPragmaCacheControl(resp.Header)

	err = readTransfer(resp, r)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RFC 7234, section 5.4: Should treat
//	Pragma: no-cache
// like
//	Cache-Control: no-cache
func fixPragmaCacheControl(header Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}

func (r *Response) closeBody() {
	if r.Body != nil {
		r.Body.Close()
	}
}

// bodyIsWritable reports whether the Body supports writing. The
// Transport returns Writable bodies for 101 Switching Protocols
// responses.
// The Transport uses this method to determine whether a persistent
// connection is done being managed from its perspective. Once we
// return a writable response body to a user, the net/http package is
// done managing that connection.
func (r *Response) bodyIsWritable() bool {
	_, ok := r.Body.(io.Writer)
	return ok
}

func (r *Response) Print() {
	fmt.Println(r.Proto, r.Status)
	var header bytes.Buffer
	err := r.Header.Write(&header)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(header.String())
	var body []byte
	if r.Body != NoBody {
		body, _ = ioutil.ReadAll(r.Body)
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		fmt.Println(string(body))
	}
}
