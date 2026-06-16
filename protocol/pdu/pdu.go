package pdu

import (
	"bytes"

	"github.com/batmanpriv/Vandor/core"
	"github.com/batmanpriv/Vandor/emission"
	"github.com/batmanpriv/Vandor/protocol/t125/gcc"
)

type PDULayer struct {
	emission.Emitter
	transport          core.Transport
	sharedId           uint32
	userId             uint16
	channelId          uint16
	serverCapabilities map[CapsType]Capability
	clientCapabilities map[CapsType]Capability
	fastPathSender     core.FastPathSender
	demandActivePDU    *DemandActivePDU
}

func NewPDULayer(t core.Transport) *PDULayer {
	p := &PDULayer{
		Emitter:   *emission.NewEmitter(),
		transport: t,
		sharedId:  0x103EA,
		serverCapabilities: map[CapsType]Capability{
			CAPSTYPE_GENERAL: &GeneralCapability{
				ProtocolVersion: 0x0200,
			},
			CAPSTYPE_BITMAP: &BitmapCapability{
				Receive1BitPerPixel:      0x0001,
				Receive4BitsPerPixel:     0x0001,
				Receive8BitsPerPixel:     0x0001,
				BitmapCompressionFlag:    0x0001,
				MultipleRectangleSupport: 0x0001,
			},
			CAPSTYPE_ORDER: &OrderCapability{
				DesktopSaveXGranularity: 1,
				DesktopSaveYGranularity: 20,
				MaximumOrderLevel:       1,
				OrderFlags:              NEGOTIATEORDERSUPPORT,
				DesktopSaveSize:         480 * 480,
			},
			CAPSTYPE_POINTER:        &PointerCapability{ColorPointerCacheSize: 20},
			CAPSTYPE_INPUT:          &InputCapability{},
			CAPSTYPE_VIRTUALCHANNEL: &VirtualChannelCapability{},
			CAPSTYPE_FONT:           &FontCapability{SupportFlags: 0x0001},
			CAPSTYPE_COLORCACHE:     &ColorCacheCapability{CacheSize: 0x0006},
			CAPSTYPE_SHARE:          &ShareCapability{},
		},
		clientCapabilities: map[CapsType]Capability{
			CAPSTYPE_GENERAL: &GeneralCapability{
				ProtocolVersion: 0x0200,
			},
			CAPSTYPE_BITMAP: &BitmapCapability{
				Receive1BitPerPixel:      0x0001,
				Receive4BitsPerPixel:     0x0001,
				Receive8BitsPerPixel:     0x0001,
				BitmapCompressionFlag:    0x0001,
				MultipleRectangleSupport: 0x0001,
			},
			CAPSTYPE_ORDER: &OrderCapability{
				DesktopSaveXGranularity: 1,
				DesktopSaveYGranularity: 20,
				MaximumOrderLevel:       1,
				OrderFlags:              NEGOTIATEORDERSUPPORT,
				DesktopSaveSize:         480 * 480,
				TextANSICodePage:        0x4e4,
			},
			CAPSTYPE_CONTROL:         &ControlCapability{0, 0, 2, 2},
			CAPSTYPE_ACTIVATION:      &WindowActivationCapability{},
			CAPSTYPE_POINTER:         &PointerCapability{1, 20, 20},
			CAPSTYPE_SHARE:           &ShareCapability{},
			CAPSTYPE_COLORCACHE:      &ColorCacheCapability{6, 0},
			CAPSTYPE_SOUND:           &SoundCapability{0x0001, 0},
			CAPSTYPE_INPUT:           &InputCapability{},
			CAPSTYPE_FONT:            &FontCapability{0x0001, 0},
			CAPSTYPE_BRUSH:           &BrushCapability{BRUSH_COLOR_8x8},
			CAPSTYPE_GLYPHCACHE:      &GlyphCapability{},
			CAPSETTYPE_BITMAP_CODECS: &BitmapCodecsCapability{},
			CAPSTYPE_BITMAPCACHE_REV2: &BitmapCache2Capability{
				BitmapCachePersist: 2,
				CachesNum:          5,
				BmpC0Cells:         0x258,
				BmpC1Cells:         0x258,
				BmpC2Cells:         0x800,
				BmpC3Cells:         0x1000,
				BmpC4Cells:         0x800,
			},
			CAPSTYPE_VIRTUALCHANNEL:        &VirtualChannelCapability{0, 1600},
			CAPSETTYPE_MULTIFRAGMENTUPDATE: &MultiFragmentUpdate{65535},
			CAPSTYPE_RAIL: &RemoteProgramsCapability{
				RailSupportLevel: RAIL_LEVEL_SUPPORTED |
					RAIL_LEVEL_SHELL_INTEGRATION_SUPPORTED |
					RAIL_LEVEL_LANGUAGE_IME_SYNC_SUPPORTED |
					RAIL_LEVEL_SERVER_TO_CLIENT_IME_SYNC_SUPPORTED |
					RAIL_LEVEL_HIDE_MINIMIZED_APPS_SUPPORTED |
					RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED |
					RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED |
					RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED,
			},
			CAPSETTYPE_LARGE_POINTER: &LargePointerCapability{1},
			CAPSETTYPE_SURFACE_COMMANDS: &SurfaceCommandsCapability{
				CmdFlags: SURFCMDS_SET_SURFACE_BITS | SURFCMDS_STREAM_SURFACE_BITS | SURFCMDS_FRAME_MARKER,
			},
			CAPSSETTYPE_FRAME_ACKNOWLEDGE: &FrameAcknowledgeCapability{2},
		},
	}

	t.On("close", func() {
		p.Emit("close")
	}).On("error", func(err error) {
		p.Emit("error", err)
	})
	return p
}

func (p *PDULayer) sendPDU(message PDUMessage) {
	pdu := NewPDU(p.userId, message)
	p.transport.Write(pdu.serialize())
}

func (p *PDULayer) sendDataPDU(message DataPDUData) {
	dataPdu := NewDataPDU(message, p.sharedId)
	p.sendPDU(dataPdu)
}

func (p *PDULayer) SetFastPathSender(f core.FastPathSender) {
	p.fastPathSender = f
}

type Client struct {
	*PDULayer
	clientCoreData *gcc.ClientCoreData
	buff           *bytes.Buffer
}

func NewClient(t core.Transport) *Client {
	c := &Client{
		PDULayer: NewPDULayer(t),
		buff:     &bytes.Buffer{},
	}
	c.transport.Once("connect", c.connect)
	return c
}

func (c *Client) connect(data *gcc.ClientCoreData, userId uint16, channelId uint16) {
	c.clientCoreData = data
	c.userId = userId
	c.channelId = channelId
	c.transport.Once("data", c.recvDemandActivePDU)
}

func (c *Client) recvDemandActivePDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, _ := readPDU(r)

	c.sharedId = pdu.Message.(*DemandActivePDU).SharedId
	c.demandActivePDU = pdu.Message.(*DemandActivePDU)
	for _, caps := range c.demandActivePDU.CapabilitySets {
		c.serverCapabilities[caps.Type()] = caps
	}

	c.sendConfirmActivePDU()
	c.sendClientFinalizeSynchronizePDU()
}

func (c *Client) sendConfirmActivePDU() {

	pdu := NewConfirmActivePDU()
	generalCapa := c.clientCapabilities[CAPSTYPE_GENERAL].(*GeneralCapability)
	generalCapa.OSMajorType = OSMAJORTYPE_WINDOWS
	generalCapa.OSMinorType = OSMINORTYPE_WINDOWS_NT
	generalCapa.ExtraFlags = LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR |
		FASTPATH_OUTPUT_SUPPORTED | AUTORECONNECT_SUPPORTED
	generalCapa.RefreshRectSupport = 0
	generalCapa.SuppressOutputSupport = 0

	bitmapCapa := c.clientCapabilities[CAPSTYPE_BITMAP].(*BitmapCapability)
	bitmapCapa.PreferredBitsPerPixel = c.clientCoreData.HighColorDepth
	bitmapCapa.DesktopWidth = c.clientCoreData.DesktopWidth
	bitmapCapa.DesktopHeight = c.clientCoreData.DesktopHeight
	bitmapCapa.DesktopResizeFlag = 0x0001

	orderCapa := c.clientCapabilities[CAPSTYPE_ORDER].(*OrderCapability)
	orderCapa.OrderFlags = NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT | ORDERFLAGS_EXTRA_FLAGS
	orderCapa.OrderSupportExFlags |= ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT
	orderCapa.OrderSupport[TS_NEG_DSTBLT_INDEX] = 1
	orderCapa.OrderSupport[TS_NEG_PATBLT_INDEX] = 1
	orderCapa.OrderSupport[TS_NEG_SCRBLT_INDEX] = 1
	orderCapa.OrderSupport[TS_NEG_FAST_GLYPH_INDEX] = 1
	inputCapa := c.clientCapabilities[CAPSTYPE_INPUT].(*InputCapability)
	inputCapa.Flags = INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE
	inputCapa.KeyboardLayout = c.clientCoreData.KbdLayout
	inputCapa.KeyboardType = c.clientCoreData.KeyboardType
	inputCapa.KeyboardSubType = c.clientCoreData.KeyboardSubType
	inputCapa.KeyboardFunctionKey = c.clientCoreData.KeyboardFnKeys
	inputCapa.ImeFileName = c.clientCoreData.ImeFileName
	glyphCapa := c.clientCapabilities[CAPSTYPE_GLYPHCACHE].(*GlyphCapability)
	glyphCapa.SupportLevel = GLYPH_SUPPORT_NONE

	pdu.SharedId = c.sharedId
	for _, v := range c.clientCapabilities {
		pdu.CapabilitySets = append(pdu.CapabilitySets, v)
	}
	pdu.NumberCapabilities = uint16(len(pdu.CapabilitySets))
	pdu.LengthSourceDescriptor = c.demandActivePDU.LengthSourceDescriptor
	pdu.SourceDescriptor = c.demandActivePDU.SourceDescriptor
	pdu.LengthCombinedCapabilities = c.demandActivePDU.LengthCombinedCapabilities

	c.sendPDU(pdu)
}

func (c *Client) sendClientFinalizeSynchronizePDU() {
	c.sendDataPDU(NewSynchronizeDataPDU(c.channelId))
	c.sendDataPDU(&ControlDataPDU{Action: CTRLACTION_COOPERATE})
	c.sendDataPDU(&ControlDataPDU{Action: CTRLACTION_REQUEST_CONTROL})
	c.sendDataPDU(&FontListDataPDU{ListFlags: 0x0003, EntrySize: 0x0032})
}

func (c *Client) RecvFastPath(secFlag byte, s []byte) {
	r := bytes.NewReader(s)
	for r.Len() > 0 {
		updateHeader, err := core.ReadUInt8(r)
		if err != nil {
			return
		}
		updateCode := updateHeader & 0x0f
		fragmentation := updateHeader & 0x30

		if err != nil {
			return
		}

		if fragmentation != FASTPATH_FRAGMENT_SINGLE {
			if fragmentation == FASTPATH_FRAGMENT_FIRST {
				c.buff.Reset()
			}
			b, _ := core.ReadBytes(r.Len(), r)
			c.buff.Write(b)
			if fragmentation != FASTPATH_FRAGMENT_LAST {
				return
			}
			r = bytes.NewReader(c.buff.Bytes())
		}

		p, err := readFastPathUpdatePDU(r, updateCode)

		if updateCode == FASTPATH_UPDATETYPE_BITMAP {
			c.Emit("bitmap", p.Data.(*FastPathBitmapUpdateDataPDU).Rectangles)
		} else if updateCode == FASTPATH_UPDATETYPE_COLOR {
			c.Emit("color", p.Data.(*FastPathColorPdu))
		} else if updateCode == FASTPATH_UPDATETYPE_ORDERS {
			c.Emit("orders", p.Data.(*FastPathOrdersPDU).OrderPdus)
		}
	}
}
