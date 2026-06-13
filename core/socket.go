package core

import (
	"crypto/rsa"
	"math/big"
	"io"
	"github.com/huin/asn1ber"

	"errors"
	"net"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"unicode/utf16"
	"github.com/icodeface/tls"
)

type SocketLayer struct {
	conn    net.Conn
	tlsConn *tls.Conn
}

func NewSocketLayer(conn net.Conn) *SocketLayer {
	l := &SocketLayer{
		conn:    conn,
		tlsConn: nil,
	}
	return l
}

func (s *SocketLayer) Read(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Read(b)
	}
	return s.conn.Read(b)
}

func (s *SocketLayer) Write(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Write(b)
	}
	return s.conn.Write(b)
}

func (s *SocketLayer) Close() error {
	if s.tlsConn != nil {
		err := s.tlsConn.Close()
		if err != nil {
			return err
		}
	}
	return s.conn.Close()
}

func (s *SocketLayer) StartTLS() error {
	config := &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS10,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}
	s.tlsConn = tls.Client(s.conn, config)
	return s.tlsConn.Handshake()
}

type PublicKey struct {
	N *big.Int `asn1:"explicit,tag:0"` // modulus
	E int      `asn1:"explicit,tag:1"` // public exponent
}

func (s *SocketLayer) TlsPubKey() ([]byte, error) {
	if s.tlsConn == nil {
		return nil, errors.New("TLS conn does not exist")
	}
	pub := s.tlsConn.ConnectionState().PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	return asn1ber.Marshal(*pub)
}

func Reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func Random(n int) []byte {
	const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alpha[b%byte(len(alpha))]
	}
	return bytes
}

func UTF16ToLittleEndianBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}
	return b
}

func LittleEndianBytesToUTF16(u []byte) []uint16 {
	b := make([]uint16, 0, len(u)/2)
	n := make([]byte, 2)
	for i, v := range u {
		if i%2 == 0 {
			n[0] = v
		} else {
			n[1] = v
			b = append(b, binary.LittleEndian.Uint16(n))
		}
	}
	return b
}

type ReadBytesComplete func(result []byte, err error)

func StartReadBytes(len int, r io.Reader, cb ReadBytesComplete) {
	b := make([]byte, len)
	go func() {
		_, err := io.ReadFull(r, b)
		cb(b, err)
	}()
}

func ReadBytes(len int, r io.Reader) ([]byte, error) {
	b := make([]byte, len)
	length, err := io.ReadFull(r, b)
	return b[:length], err
}

func ReadByte(r io.Reader) (byte, error) {
	b, err := ReadBytes(1, r)
	return b[0], err
}

func ReadUInt8(r io.Reader) (uint8, error) {
	b, err := ReadBytes(1, r)
	return uint8(b[0]), err
}

func ReadUint16LE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.LittleEndian.Uint16(b), nil
}

func ReadUint16BE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.BigEndian.Uint16(b), nil
}

func ReadUInt32LE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.LittleEndian.Uint32(b), nil
}

func ReadUInt32BE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.BigEndian.Uint32(b), nil
}

func WriteByte(data byte, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func WriteBytes(data []byte, w io.Writer) (int, error) {
	return w.Write(data)
}

func WriteUInt8(data uint8, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func WriteUInt16BE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return w.Write(b)
}

func WriteUInt16LE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, data)
	return w.Write(b)
}

func WriteUInt32LE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, data)
	return w.Write(b)
}

func WriteUInt32BE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return w.Write(b)
}

func PutUint16BE(data uint16) (uint8, uint8) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return uint8(b[0]), uint8(b[1])
}

func Uint16BE(d0, d1 uint8) uint16 {
	b := make([]byte, 2)
	b[0] = d0
	b[1] = d1

	return binary.BigEndian.Uint16(b)
}

func RGB565ToRGB(data uint16) (r, g, b uint8) {
	r = uint8(data & 0xF800 >> 8)
	g = uint8(data & 0x07E0 >> 3)
	b = uint8(data & 0x001F << 3)

	return
}
func RGB555ToRGB(data uint16) (r, g, b uint8) {
	r = uint8(data & 0x7C00 >> 7)
	g = uint8(data & 0x03E0 >> 2)
	b = uint8(data & 0x001F << 3)

	return
}

func UnicodeEncode(p string) []byte {
	return UTF16ToLittleEndianBytes(utf16.Encode([]rune(p)))
}

func UnicodeDecode(p []byte) string {
	r := bytes.NewReader(p)
	n := make([]uint16, 0, 100)
	for r.Len() > 0 {
		a, _ := ReadUint16LE(r)
		n = append(n, a)
	}
	return string(utf16.Decode(n))
}

func BytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}
