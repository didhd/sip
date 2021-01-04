package sip

// Here are all the SIP methods.
const (
	MethodInvite    = "INVITE"    // INVITE	[RFC3261]
	MethodAck       = "ACK"       // ACK	[RFC3261]
	MethodBye       = "BYE"       // BYE	[RFC3261]
	MethodCancel    = "CANCEL"    // CANCEL	[RFC3261]
	MethodOptions   = "OPTIONS"   // OPTIONS	[RFC3261]
	MethodRegister  = "REGISTER"  // REGISTER	[RFC3261]
	MethodPrack     = "PRACK"     // PRACK	[RFC3262]
	MethodSubscribe = "SUBSCRIBE" // SUBSCRIBE	[RFC6665]
	MethodNotify    = "NOTIFY"    // NOTIFY	[RFC6665]
	MethodPublish   = "PUBLISH"   // PUBLISH	[RFC3903]
	MethodInfo      = "INFO"      // INFO	[RFC6086]
	MethodRefer     = "REFER"     // REFER	[RFC3515]
	MethodMessage   = "MESSAGE"   // MESSAGE	[RFC3428]
	MethodUpdate    = "UPDATE"    // UPDATE	[RFC3311]
	MethodPing      = "PING"      // PING	[https://tools.ietf.org/html/draft-fwmiller-ping-03]
)
