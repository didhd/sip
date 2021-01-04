package sip

import (
	"bytes"
	"strings"
	"testing"
)

const inviteRequestString = `INVITE tel:+821012346789 SIP/2.0
User-Agent: Go-sip-client/1.0
Content-Length: 3
From: <tel:+821012345678>;tag=9230d303
To: <tel:+821012346789>

v=0`

func TestWriteRequest(t *testing.T) {
	// Request
	req, err := NewRequest("INVITE", "tel:+821012346789", strings.NewReader("v=0"))
	if err != nil {
		t.Error(err)
	}
	req.Header.Set("From", "<tel:+821012345678>;tag=9230d303")
	req.Header.Set("To", "<tel:+821012346789>")

	var out bytes.Buffer
	err = req.Write(&out)
	if err != nil {
		t.Error(err)
	}

	expected := strings.NewReplacer("\n", "\r\n").Replace(inviteRequestString)

	if out.String() != expected {
		t.Errorf("output=%q\n expected %q", out.String(), expected)
	}
}
