package sip

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
)

const Response200OK = `SIP/2.0 200 OK
Content-Length: 10

Body here`

func TestReadResponse(t *testing.T) {
	raw := strings.NewReplacer("\n", "\r\n").Replace(Response200OK)

	br := bufio.NewReader(strings.NewReader(raw))
	resp, err := ReadResponse(br, &Request{Method: "INVITE"})
	if err != nil {
		fmt.Println(err)
	}

	if resp.ContentLength != 10 {
		t.Errorf("output=%q\n expected %q", resp.ContentLength, 10)
	}

	if resp.Proto != "SIP/2.0" {
		t.Errorf("output=%q\n expected %q", resp.Proto, "SIP/2.0")
	}
}
