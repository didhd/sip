package sip

// import (
// 	"bytes"
// 	"strings"
// 	"testing"
// )

// const emptyBody = ""

// func TestClientDoWithProxy(t *testing.T) {
// 	// Create client.
// 	c := &Client{}

// 	// First Request
// 	req, err := NewRequest("REGISTER", "sip:example.com", strings.NewReader(emptyBody))
// 	req.SetProxy("sips:localhost:8183")
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	req.Header.Set("Via", "SIP/2.0/TLS localhost:8183;branch=z9hG4bK-524287-1---8d7376c5279ca6ce;rport;keep;transport=TLS")
// 	req.Header.Set("Max-Forwards", "70")
// 	req.Header.Set("Contact", "<sip:+821012345678@localhost:8183>;reg-id=1;+sip.instance=\"<urn:gsma:imei:35352409-002176-0>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.botversion=\"#=1\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\"")
// 	req.Header.Set("To", "<sip:+821012345678@example.com>")
// 	req.Header.Set("From", "<sip:+821012345678@example.com>;tag=42f90769")
// 	req.Header.Set("Call-ID", "3YEDsB2TlGG5yiH89nyY9A..@localhost")
// 	req.Header.Set("CSeq", "2 REGISTER")
// 	req.Header.Set("Expires", "600000")
// 	req.Header.Set("Supported", "path")
// 	req.Header.Set("User-Agent", "Go-Sip")
// 	req.Header.Set("Authorization", "Digest username=\"+821012345678@example.com\",realm=\"example.com\",uri=\"sip:example.com\",nonce=\"5e12c3ca91c416d1734cd8306ae82b1f625885f5\",response=\"c4f3182310004085cd05a015a6aa653e\",algorithm=MD5,nc=00000001,qop=auth,cnonce=\"0a4f113b\",opaque=\"004533235332435434ffac663e\"")
// 	req.Header.Set("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=45008040d0b1f711")

// 	req.Print()

// 	// Roundtrip
// 	resp, err := c.Do(req)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer resp.Body.Close()

// 	resp.Print()

// 	// Second Request
// 	inviteBody := `v=0
// o=SAMSUNG-IMS-UE 1573714258742059 0 IN IP4 localhost
// s=SS VOIP
// c=IN IP4 localhost
// t=0 0
// m=message 8881 TCP/MSRP *
// a=accept-types:message/cpim application/im-iscomposing+xml
// a=accept-wrapped-types:text/plain message/imdn+xml application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml
// a=setup:actpass
// a=path:msrp://localhost:8881/71f1vpJTi3rhgHUHj;tcp
// a=sendrecv
// a=fingerprint:sha-1 01:43:E3:69:F7:8F:0B:50:F8:31:56:AC:14:C7:0F:E8:99:DB:26:82`

// 	req2, err := NewRequest("INVITE", "tel:+821023456789", bytes.NewBuffer([]byte(inviteBody)))
// 	req2.SetProxy("sips:localhost:8183")
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	req2.Header.Set("Via", "SIP/2.0/TLS localhost:8183;branch=z9hG4bK-524287-1---fa0a15ec4e38b9f0;rport;transport=TLS")
// 	req2.Header.Set("Max-Forwards", "70")
// 	req2.Header.Set("Contact", "<sip:+821012345678@localhost:8183>;reg-id=1;+sip.instance=\"<urn:gsma:imei:35352409-002176-0>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.botversion=\"#=1\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\"")
// 	req2.Header.Set("To", "<tel:+821023456789>")
// 	req2.Header.Set("From", "<tel:+821012345678>;tag=9230d306")
// 	req2.Header.Set("Call-ID", "ILsIKDx0iMWisCH19-T9cg..@localhost")
// 	req2.Header.Set("CSeq", "1 INVITE")
// 	req2.Header.Set("Session-Expires", "7200;refresher=uac")
// 	req2.Header.Set("Min-SE", "90")
// 	req2.Header.Set("Accept", "application/sdp")
// 	req2.Header.Set("Allow", "INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK")
// 	req2.Header.Set("Content-Type", "application/sdp")
// 	req2.Header.Set("Supported", "timer")
// 	req2.Header.Set("User-Agent", "Go-Sip")
// 	req2.Header.Set("Accept-Contact", "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"")
// 	req2.Header.Set("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session")
// 	req2.Header.Set("P-Preferred-Identity", "<tel:+821012345678>")
// 	req2.Header.Set("Conversation-ID", "a4e77d31-5ef9-40b4-801a-c2614bdaba71")
// 	req2.Header.Set("Contribution-ID", "21d73b53-2066-4673-87c8-c340092ba3fd")
// 	req2.Header.Set("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=45008040d0b1f711")

// 	req2.Print()

// 	// Second roundtrip
// 	resp2, err := c.Do(req2)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer resp2.Body.Close()

// 	resp2.Print()
// }

// func TestClientDo(t *testing.T) {
// 	// Create client.
// 	c := &Client{}

// 	// First Request
// 	req, err := NewRequest("REGISTER", "sip:localhost:8182", strings.NewReader(emptyBody))
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	req.Header.Set("Via", "SIP/2.0/TLS localhost:8183;branch=z9hG4bK-524287-1---8d7376c5279ca6ce;rport;keep;transport=TLS")
// 	req.Header.Set("Max-Forwards", "70")
// 	req.Header.Set("Contact", "<sip:+821012345678@localhost:8183>;reg-id=1;+sip.instance=\"<urn:gsma:imei:35352409-002176-0>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.botversion=\"#=1\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\"")
// 	req.Header.Set("To", "<sip:+821012345678@example.com>")
// 	req.Header.Set("From", "<sip:+821012345678@example.com>;tag=42f90769")
// 	req.Header.Set("Call-ID", "3YEDsB2TlGG5yiH89nyY9C..@localhost")
// 	req.Header.Set("CSeq", "2 REGISTER")
// 	req.Header.Set("Expires", "600000")
// 	req.Header.Set("Supported", "path")
// 	req.Header.Set("User-Agent", "Go-Sip")
// 	req.Header.Set("Authorization", "Digest username=\"+821012345678@example.com\",realm=\"example.com\",uri=\"sip:example.com\",nonce=\"5e12c3ca91c416d1734cd8306ae82b1f625885f5\",response=\"c4f3182310004085cd05a015a6aa653e\",algorithm=MD5,nc=00000001,qop=auth,cnonce=\"0a4f113b\",opaque=\"004533235332435434ffac663e\"")
// 	req.Header.Set("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=45008040d0b1f711")

// 	req.Print()

// 	// Roundtrip
// 	resp, err := c.Do(req)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer resp.Body.Close()

// 	resp.Print()
// }

// func TestClientDoTLS(t *testing.T) {
// 	// Create client.
// 	c := &Client{}

// 	// First Request
// 	req, err := NewRequest("REGISTER", "sips:localhost:8183", strings.NewReader(emptyBody))
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	req.Header.Set("Via", "SIP/2.0/TLS localhost:8183;branch=z9hG4bK-524287-1---8d7376c5279ca6ce;rport;keep;transport=TLS")
// 	req.Header.Set("Max-Forwards", "70")
// 	req.Header.Set("Contact", "<sip:+821012345678@localhost:8183>;reg-id=1;+sip.instance=\"<urn:gsma:imei:35352409-002176-0>\";q=1.0;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.botversion=\"#=1\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\"")
// 	req.Header.Set("To", "<sip:+821012345678@example.com>")
// 	req.Header.Set("From", "<sip:+821012345678@example.com>;tag=42f90769")
// 	req.Header.Set("Call-ID", "3YEDsB2TlGG5yiH89nyY9C..@localhost")
// 	req.Header.Set("CSeq", "2 REGISTER")
// 	req.Header.Set("Expires", "600000")
// 	req.Header.Set("Supported", "path")
// 	req.Header.Set("User-Agent", "Go-Sip")
// 	req.Header.Set("Authorization", "Digest username=\"+821012345678@example.com\",realm=\"example.com\",uri=\"sip:example.com\",nonce=\"5e12c3ca91c416d1734cd8306ae82b1f625885f5\",response=\"c4f3182310004085cd05a015a6aa653e\",algorithm=MD5,nc=00000001,qop=auth,cnonce=\"0a4f113b\",opaque=\"004533235332435434ffac663e\"")
// 	req.Header.Set("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=45008040d0b1f711")

// 	req.Print()

// 	// Roundtrip
// 	resp, err := c.Do(req)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer resp.Body.Close()

// 	resp.Print()
// }
