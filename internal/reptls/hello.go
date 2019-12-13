package reptls

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// TLS handshake types.
	typeServerHello uint8 = 2
)

// A ServerHello message. Only includes a subset of fields on the message.
type ServerHello struct {
	Version, Suite uint16
	Random         []byte
}

// ParseServerHello parses a server hello message.
func ParseServerHello(b []byte) (*ServerHello, error) {
	msgType, b, err := parseHandshakeHeader(b)
	if err != nil {
		return nil, err
	}
	if msgType != typeServerHello {
		return nil, fmt.Errorf("expected server hello message, got TLS handshake type %d", b[0])
	}

	m := new(serverHelloMsg)
	if !m.unmarshal(b) {
		return nil, fmt.Errorf("malformed message")
	}
	if m.supportedVersion != 0 {
		return &ServerHello{m.supportedVersion, m.cipherSuite, m.random}, nil
	}
	return &ServerHello{m.vers, m.cipherSuite, m.random}, nil
}

func parseHandshakeHeader(b []byte) (msgType uint8, rest []byte, err error) {
	const minLen = recordHeaderLen + 4 // 4 bytes is the minimum hello message size
	if len(b) < minLen {
		return 0, nil, fmt.Errorf("message of length %d bytes is less than minimum of %d bytes", len(b), minLen)
	}

	version := uint16(b[1])<<8 | uint16(b[2])
	cs := &ConnState{version: version, cipherSuite: uninitializedSuite{}}
	b, _, err = readRecord(bytes.NewReader(b), new(bytes.Buffer), cs, [52]byte{}, [16]byte{}, recordTypeHandshake)
	if err != nil {
		return 0, nil, err
	}

	msgType = b[0]
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n > maxHandshake {
		return 0, nil, fmt.Errorf("message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake)
	}
	if len(b) < 4+n {
		return 0, nil, fmt.Errorf("message too small: length specified as %d, but actually %d", 4+n, len(b))
	}
	return msgType, b[:n+4], nil
}

type serverHelloMsg struct {
	raw                          []byte
	vers                         uint16
	random                       []byte
	sessionID                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionID) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			for !extData.Empty() {
				var proto cryptobyte.String
				if !extData.ReadUint8LengthPrefixed(&proto) ||
					proto.Empty() {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(proto))
			}
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSessionTicket:
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.scts = append(m.scts, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return false
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return false
				}
			}
		case extensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51

	extensionNextProtoNeg      uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type CurveID uint16

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

type uninitializedSuite struct{}

func (s uninitializedSuite) getCipher(_ [52]byte, _ [16]byte, _ bool, _ uint16) (interface{}, macFunction) {
	return nil, nil
}
