This corpus was generated under:

- Date: Wed Sep 15 13:03:25 CEST 2021
- Commit: a9d7987
- tls.Config: (*tls.Config)(0xc000106900)({
 Rand: (fuzzutil.MathRandReader) 0,
 Time: (func() time.Time) <nil>,
 Certificates: ([]tls.Certificate) <nil>,
 NameToCertificate: (map[string]*tls.Certificate) <nil>,
 GetCertificate: (func(*tls.ClientHelloInfo) (*tls.Certificate, error)) <nil>,
 GetClientCertificate: (func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) <nil>,
 GetConfigForClient: (func(*tls.ClientHelloInfo) (*tls.Config, error)) <nil>,
 VerifyPeerCertificate: (func([][]uint8, [][]*x509.Certificate) error) <nil>,
 VerifyConnection: (func(tls.ConnectionState) error) <nil>,
 RootCAs: (*x509.CertPool)(<nil>),
 NextProtos: ([]string) <nil>,
 ServerName: (string) "",
 ClientAuth: (tls.ClientAuthType) NoClientCert,
 ClientCAs: (*x509.CertPool)(<nil>),
 InsecureSkipVerify: (bool) true,
 CipherSuites: ([]uint16) <nil>,
 PreferServerCipherSuites: (bool) false,
 SessionTicketsDisabled: (bool) false,
 SessionTicketKey: ([32]uint8) (len=32 cap=32) {
  00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
  00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 },
 ClientSessionCache: (tls.ClientSessionCache) <nil>,
 MinVersion: (uint16) 0,
 MaxVersion: (uint16) 0,
 CurvePreferences: ([]tls.CurveID) <nil>,
 DynamicRecordSizingDisabled: (bool) false,
 Renegotiation: (tls.RenegotiationSupport) 0,
 KeyLogWriter: (io.Writer) <nil>,
 mutex: (sync.RWMutex) {
  w: (sync.Mutex) {
   state: (int32) 0,
   sema: (uint32) 0
  },
  writerSem: (uint32) 0,
  readerSem: (uint32) 0,
  readerCount: (int32) 0,
  readerWait: (int32) 0
 },
 sessionTicketKeys: ([]tls.ticketKey) <nil>,
 autoSessionTicketKeys: ([]tls.ticketKey) <nil>
})

