package encoding

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

func legacyBodySecurity(security protocol.SecurityType) bool {
	return security == protocol.SecurityType_AES128_CFB || security == protocol.SecurityType_NONE
}

func validateLegacyBodyOptions(request *protocol.RequestHeader) error {
	allowed := protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding
	if request.Option & ^allowed != 0 {
		return errors.New("unsupported legacy VMess body options")
	}
	if request.Option.Has(protocol.RequestOptionGlobalPadding) && !request.Option.Has(protocol.RequestOptionChunkMasking) {
		return errors.New("legacy VMess padding requires chunk masking")
	}
	if request.Command != protocol.RequestCommandTCP && request.Command != protocol.RequestCommandUDP && request.Command != protocol.RequestCommandMux {
		return errors.New("unsupported legacy VMess body command")
	}
	if !request.Option.Has(protocol.RequestOptionChunkStream) && (request.Security != protocol.SecurityType_NONE || request.Command != protocol.RequestCommandTCP || request.Option != 0) {
		return errors.New("unframed VMess NONE is TCP-only with no options")
	}
	return nil
}

// Legacy FNV is an unkeyed checksum, not cryptographic authentication. These
// explicit compatibility body modes do not select the header authentication mode.
type legacyBodyAuth struct{ checksum bool }

func (a legacyBodyAuth) NonceSize() int { return 0 }
func (a legacyBodyAuth) Overhead() int {
	if a.checksum {
		return 4
	}
	return 0
}

func (a legacyBodyAuth) Seal(dst, plain []byte) ([]byte, error) {
	if !a.checksum {
		return append(dst, plain...), nil
	}
	sum := Authenticate(plain)
	start, size := len(dst), len(dst)+4+len(plain)
	out := dst
	if cap(out) >= size {
		out = out[:size]
	} else {
		out = make([]byte, size)
		copy(out, dst)
	}
	copy(out[start+4:], plain)
	binary.BigEndian.PutUint32(out[start:start+4], sum)
	return out, nil
}

func (a legacyBodyAuth) Open(dst, wire []byte) ([]byte, error) {
	if a.checksum {
		if len(wire) < 4 || binary.BigEndian.Uint32(wire[:4]) != Authenticate(wire[4:]) {
			return nil, errors.New("invalid VMess CFB checksum")
		}
		wire = wire[4:]
	}
	return append(dst, wire...), nil
}

type legacyPadding struct {
	crypto.PaddingLengthGenerator
	last uint16
}

func (p *legacyPadding) NextPaddingLen() uint16 {
	p.last = p.PaddingLengthGenerator.NextPaddingLen()
	return p.last
}

type checkedLegacySize struct {
	crypto.ChunkSizeDecoder
	overhead uint16
	padding  *legacyPadding
}

func (s checkedLegacySize) Decode(wire []byte) (uint16, error) {
	size, err := s.ChunkSizeDecoder.Decode(wire)
	if err != nil {
		return 0, err
	}
	minimum := s.overhead
	if s.padding != nil {
		minimum += s.padding.last
	}
	if size < minimum {
		return 0, errors.New("legacy VMess chunk shorter than checksum/padding")
	}
	return size, nil
}

func newLegacyBodyReader(request *protocol.RequestHeader, key, iv []byte, reader io.Reader) (buf.Reader, error) {
	return legacyBodyReader(request, key, iv, reader, false)
}

func legacyBodyReader(request *protocol.RequestHeader, key, iv []byte, reader io.Reader, cipherReady bool) (buf.Reader, error) {
	if err := validateLegacyBodyOptions(request); err != nil {
		return nil, err
	}
	if !request.Option.Has(protocol.RequestOptionChunkStream) {
		return buf.NewReader(reader), nil
	}
	var size crypto.ChunkSizeDecoder = crypto.PlainChunkSizeParser{}
	var padding *legacyPadding
	if request.Option.Has(protocol.RequestOptionChunkMasking) {
		shake := NewShakeSizeParser(iv)
		size = shake
		if request.Option.Has(protocol.RequestOptionGlobalPadding) {
			padding = &legacyPadding{PaddingLengthGenerator: shake}
		}
	}
	if request.Security == protocol.SecurityType_NONE && padding == nil && request.Command.TransferType() == protocol.TransferTypeStream {
		return crypto.NewChunkStreamReader(size, reader), nil
	}
	auth := legacyBodyAuth{checksum: request.Security == protocol.SecurityType_AES128_CFB}
	if auth.checksum && !cipherReady {
		reader = crypto.NewCryptionReader(crypto.NewAesDecryptionStream(key, iv), reader)
	}
	var generator crypto.PaddingLengthGenerator
	if padding != nil {
		generator = padding
	}
	return crypto.NewAuthenticationReader(auth, checkedLegacySize{ChunkSizeDecoder: size, overhead: uint16(auth.Overhead()), padding: padding}, reader, request.Command.TransferType(), generator), nil
}

func newLegacyBodyWriter(request *protocol.RequestHeader, key, iv []byte, writer io.Writer) (buf.Writer, error) {
	return legacyBodyWriter(request, key, iv, writer, false)
}

func legacyBodyWriter(request *protocol.RequestHeader, key, iv []byte, writer io.Writer, cipherReady bool) (buf.Writer, error) {
	if err := validateLegacyBodyOptions(request); err != nil {
		return nil, err
	}
	if !request.Option.Has(protocol.RequestOptionChunkStream) {
		return buf.NewWriter(writer), nil
	}
	var size crypto.ChunkSizeEncoder = crypto.PlainChunkSizeParser{}
	var padding crypto.PaddingLengthGenerator
	if request.Option.Has(protocol.RequestOptionChunkMasking) {
		shake := NewShakeSizeParser(iv)
		size = shake
		if request.Option.Has(protocol.RequestOptionGlobalPadding) {
			padding = shake
		}
	}
	if request.Security == protocol.SecurityType_NONE && padding == nil && request.Command.TransferType() == protocol.TransferTypeStream {
		return crypto.NewChunkStreamWriter(size, writer), nil
	}
	auth := legacyBodyAuth{checksum: request.Security == protocol.SecurityType_AES128_CFB}
	if auth.checksum && !cipherReady {
		writer = crypto.NewCryptionWriter(crypto.NewAesEncryptionStream(key, iv), writer)
	}
	output := crypto.NewAuthenticationWriter(auth, size, writer, request.Command.TransferType(), padding)
	if request.Command.TransferType() == protocol.TransferTypePacket {
		limit := int32(buf.Size-auth.Overhead()) - size.SizeBytes()
		if padding != nil {
			limit -= int32(padding.MaxPaddingLen())
		}
		return legacyPacketWriter{Writer: output, limit: limit}, nil
	}
	return output, nil
}

// The shared packet writer drops overlarge packets. Reject the entire batch
// explicitly before writing any of it instead of reporting a false success.
type legacyPacketWriter struct {
	buf.Writer
	limit int32
}

func (w legacyPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if b.Len() > w.limit {
			buf.ReleaseMulti(mb)
			return errors.New("legacy VMess datagram exceeds safe frame size")
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}
