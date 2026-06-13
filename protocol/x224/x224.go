package x224

import (
	"bytes"
	"errors"

	"github.com/batmanpriv/Vandor/core"
	"github.com/batmanpriv/Vandor/emission"
	"github.com/batmanpriv/Vandor/protocol/tpkt"

	"github.com/lunixbochs/struc"
)

type MessageType byte

const (
	TPDU_CONNECTION_REQUEST MessageType = 0xE0
	TPDU_CONNECTION_CONFIRM             = 0xD0
	TPDU_DISCONNECT_REQUEST             = 0x80
	TPDU_DATA                           = 0xF0
	TPDU_ERROR                          = 0x70
)

type NegotiationType byte

const (
	TYPE_RDP_NEG_REQ     NegotiationType = 0x01
	TYPE_RDP_NEG_RSP                     = 0x02
	TYPE_RDP_NEG_FAILURE                 = 0x03
)

const (
	PROTOCOL_RDP       uint32 = 0x00000000
	PROTOCOL_SSL              = 0x00000001
	PROTOCOL_HYBRID           = 0x00000002
	PROTOCOL_HYBRID_EX        = 0x00000008
)

type Negotiation struct {
	Type   NegotiationType `struc:"byte"`
	Flag   uint8           `struc:"uint8"`
	Length uint16          `struc:"little"`
	Result uint32          `struc:"little"`
}

func NewNegotiation() *Negotiation {
	return &Negotiation{0, 0, 0x0008 /*constant*/, PROTOCOL_RDP}
}

const (
	SSL_REQUIRED_BY_SERVER = 0x00000001

	SSL_NOT_ALLOWED_BY_SERVER = 0x00000002

	SSL_CERT_NOT_ON_SERVER = 0x00000003

	INCONSISTENT_FLAGS = 0x00000004

	HYBRID_REQUIRED_BY_SERVER = 0x00000005

	SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006
)

type ClientConnectionRequestPDU struct {
	Len               uint8
	Code              MessageType
	Padding1          uint16
	Padding2          uint16
	Padding3          uint8
	Cookie            []byte
	requestedProtocol uint32
	ProtocolNeg       *Negotiation
}

func NewClientConnectionRequestPDU(cookie []byte, requestedProtocol uint32) *ClientConnectionRequestPDU {
	x := ClientConnectionRequestPDU{0, TPDU_CONNECTION_REQUEST, 0, 0, 0,
		cookie, requestedProtocol, NewNegotiation()}

	x.Len = 6
	if len(cookie) > 0 {
		x.Len += uint8(len(cookie) + 2)
	}
	if x.requestedProtocol > PROTOCOL_RDP {
		x.Len += 8
	}

	return &x
}

func (x *ClientConnectionRequestPDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt8(x.Len, buff)
	core.WriteUInt8(uint8(x.Code), buff)
	core.WriteUInt16BE(x.Padding1, buff)
	core.WriteUInt16BE(x.Padding2, buff)
	core.WriteUInt8(x.Padding3, buff)

	if len(x.Cookie) > 0 {
		buff.Write(x.Cookie)
		core.WriteUInt8(0x0D, buff)
		core.WriteUInt8(0x0A, buff)
	}

	if x.requestedProtocol > PROTOCOL_RDP {
		struc.Pack(buff, x.ProtocolNeg)
	}

	return buff.Bytes()
}

type ServerConnectionConfirm struct {
	Len         uint8
	Code        MessageType
	Padding1    uint16
	Padding2    uint16
	Padding3    uint8
	ProtocolNeg *Negotiation
}

type DataHeader struct {
	Header      uint8       `struc:"little"`
	MessageType MessageType `struc:"uint8"`
	Separator   uint8       `struc:"little"`
}

func NewDataHeader() *DataHeader {
	return &DataHeader{2, TPDU_DATA /* constant */, 0x80 /*constant*/}
}

type X224 struct {
	emission.Emitter
	transport         core.Transport
	requestedProtocol uint32
	selectedProtocol  uint32
	dataHeader        *DataHeader
}

func New(t core.Transport) *X224 {
	x := &X224{
		*emission.NewEmitter(),
		t,
		PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID,
		PROTOCOL_SSL,
		NewDataHeader(),
	}

	t.On("close", func() {
		x.Emit("close")
	}).On("error", func(err error) {
		x.Emit("error", err)
	})

	return x
}

func (x *X224) Read(b []byte) (n int, err error) {
	return x.transport.Read(b)
}

func (x *X224) Write(b []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	err = struc.Pack(buff, x.dataHeader)
	if err != nil {
		return 0, err
	}
	buff.Write(b)
	return x.transport.Write(buff.Bytes())
}

func (x *X224) Close() error {
	return x.transport.Close()
}

func (x *X224) SetRequestedProtocol(p uint32) {
	x.requestedProtocol = p
}

func (x *X224) Connect() error {
	if x.transport == nil {
		return errors.New("no transport")
	}
	cookie := "Cookie: mstshash=test"
	message := NewClientConnectionRequestPDU([]byte(cookie), x.requestedProtocol)
	message.ProtocolNeg.Type = TYPE_RDP_NEG_REQ
	message.ProtocolNeg.Result = uint32(x.requestedProtocol)

	_, err := x.transport.Write(message.Serialize())
	x.transport.Once("data", x.recvConnectionConfirm)
	return err
}

func (x *X224) recvConnectionConfirm(s []byte) {

	r := bytes.NewReader(s)
	ln, _ := core.ReadUInt8(r)
	if ln > 6 {
		message := &ServerConnectionConfirm{}
		if err := struc.Unpack(bytes.NewReader(s), message); err != nil {
			return
		}
		if message.ProtocolNeg.Type == TYPE_RDP_NEG_FAILURE {

			if message.ProtocolNeg.Result == 2 {
			}
			x.Close()
			return
		}

		if message.ProtocolNeg.Type == TYPE_RDP_NEG_RSP {
			x.selectedProtocol = message.ProtocolNeg.Result
		}
	} else {
		x.selectedProtocol = PROTOCOL_RDP
	}

	if x.selectedProtocol == PROTOCOL_HYBRID_EX {
		return
	}

	x.transport.On("data", x.recvData)

	if x.selectedProtocol == PROTOCOL_RDP {
		x.Emit("connect", x.selectedProtocol)
		return
	}

	if x.selectedProtocol == PROTOCOL_SSL {

		err := x.transport.(*tpkt.TPKT).StartTLS()
		if err != nil {
			return
		}
		x.Emit("connect", x.selectedProtocol)
		return
	}

	if x.selectedProtocol == PROTOCOL_HYBRID {
		err := x.transport.(*tpkt.TPKT).StartNLA()
		if err != nil {
			return
		}
		x.Emit("connect", x.selectedProtocol)
		return
	}
}

func (x *X224) recvData(s []byte) {
	x.Emit("data", s[3:])
}
