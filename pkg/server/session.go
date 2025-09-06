// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nttcom/pola/internal/pkg/cspf"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/packet/pcep"

	"go.uber.org/zap"
)

type SessionType string

const (
	SessionTypePCEP  SessionType = "pcep"
	SessionTypeHPCEP SessionType = "hpcep"
)

type Session struct {
	Mode            PCEMode
	SessionType     SessionType
	SessionID       uint8
	PeerAddr        netip.Addr
	TCPConn         *net.TCPConn
	IsSynced        bool
	SRPIDHead       uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	SRPolicies      []*table.SRPolicy
	Logger          *zap.Logger
	KeepAlive       uint8
	PCCType         pcep.PccType
	PCCCapabilities []pcep.CapabilityInterface
	TED             *table.LsTED
	LocalDomainID   uint32 // Local domain ID
	PeerDomainID    uint32 // Peer domain ID (for H-PCE sessions)
}

func NewSession(sessionID uint8, peerAddr netip.Addr, tcpConn *net.TCPConn, logger *zap.Logger, ted *table.LsTED, mode PCEMode, sessionType SessionType, localDomainID uint32) *Session {
	return &Session{
		SessionID:     sessionID,
		IsSynced:      false,
		SRPIDHead:     uint32(1),
		Logger:        logger.With(zap.String("server", "pcep"), zap.String("session", peerAddr.String())),
		PCCType:       pcep.RFCCompliant,
		PeerAddr:      peerAddr,
		TCPConn:       tcpConn,
		TED:           ted,
		Mode:          mode,
		SessionType:   sessionType,
		LocalDomainID: localDomainID,
		PeerDomainID:  0, // Initialize as 0
	}
}

// EstablishUnified provides unified session establishment for all modes
func (ss *Session) Established() {
	// Step 1: Perform OPEN exchange based on mode
	if err := ss.OpenExchange(); err != nil {
		ss.Logger.Debug("ERROR! OPEN exchange failed", zap.String("mode", string(ss.Mode)), zap.Error(err))
		return
	}

	ss.Logger.Debug("PCEP session established", zap.String("mode", string(ss.Mode)))

	// Step 2: Send initial keepalive
	if err := ss.SendKeepalive(); err != nil {
		ss.Logger.Debug("ERROR! Send Keepalive Message", zap.Error(err))
		return
	}

	// Step 3: Perform mode-specific initialization
	if err := ss.SpecificInit(); err != nil {
		ss.Logger.Debug("ERROR! Mode-specific initialization", zap.String("mode", string(ss.Mode)), zap.Error(err))
		return
	}

	// Step 4: Start main message loop
	done := make(chan struct{})
	defer close(done)

	// Start PCEP message receiver goroutine
	go func() {
		if err := ss.ReceivePCEPMessage(); err != nil {
			ss.Logger.Debug("ERROR! Receive PCEP Message", zap.Error(err))
		}
		done <- struct{}{}
	}()

	// Start keepalive timer
	ticker := time.NewTicker(time.Duration(ss.KeepAlive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			ss.Logger.Info("Session terminated", zap.String("mode", string(ss.Mode)), zap.String("peer-addr", ss.PeerAddr.String()))
			return
		case <-ticker.C:
			if err := ss.SendKeepalive(); err != nil {
				ss.Logger.Debug("ERROR! Send Keepalive Message", zap.Error(err))
				done <- struct{}{}
			}
		}
	}
}

// performOpenExchange handles OPEN message exchange based on mode
func (ss *Session) OpenExchange() error {
	switch ss.Mode {
	case ModePCE, ModeParentPCE:
		// Server mode: Receive OPEN first, then send OPEN response
		return ss.Open()
	case ModePCC:
		return ss.OpenAsClient()
	case ModeChildPCE:
		switch ss.SessionType {
		case SessionTypePCEP:
			return ss.Open()
		case SessionTypeHPCEP:
			return ss.OpenAsClient()
		default:
			return fmt.Errorf("unsupported session type: %s", ss.SessionType)
		}
	default:
		return fmt.Errorf("unsupported mode: %s", ss.Mode)
	}
}

// performModeSpecificInit handles mode-specific initialization after OPEN exchange
func (ss *Session) SpecificInit() error {
	if ss.Mode == ModePCC || (ss.Mode == ModeChildPCE && ss.SessionType == SessionTypeHPCEP) {
		// Client modes: Send sync completion to mark session as synced
		if err := ss.SendSyncCompletion(); err != nil {
			return err
		}
		ss.IsSynced = true
		ss.Logger.Info("Session sync completed", zap.String("mode", string(ss.Mode)), zap.String("peer-addr", ss.PeerAddr.String()))
	}
	return nil
}

func (ss *Session) sendPCEPMessage(message pcep.Message) error {
	byteMessage, err := message.Serialize()
	if err != nil {
		return err
	}
	if _, err = ss.TCPConn.Write(byteMessage); err != nil {
		return err
	}
	return nil
}

func (ss *Session) Open() error {
	if err := ss.ReceiveOpen(); err != nil {
		return err
	}

	return ss.SendOpen()
}

func (ss *Session) OpenAsClient() error {
	if err := ss.SendOpenAsClient(); err != nil {
		return err
	}

	return ss.ReceiveOpen()
}

func (ss *Session) parseOpenMessage() (*pcep.OpenMessage, error) {
	byteOpenHeader := make([]uint8, pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(byteOpenHeader); err != nil {
		return nil, err
	}

	var openHeader pcep.CommonHeader
	if err := openHeader.DecodeFromBytes(byteOpenHeader); err != nil {
		return nil, err
	}

	if openHeader.Version != 1 {
		return nil, fmt.Errorf("PCEP version mismatch (receive version: %d)", openHeader.Version)
	}
	if openHeader.MessageType != pcep.MessageTypeOpen {
		return nil, fmt.Errorf("this peer has not been opened (messageType: %s)", openHeader.MessageType.String())
	}

	byteOpenObject := make([]uint8, openHeader.MessageLength-pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(byteOpenObject); err != nil {
		return nil, err
	}

	var openMessage pcep.OpenMessage
	if err := openMessage.DecodeFromBytes(byteOpenObject); err != nil {
		return nil, err
	}

	return &openMessage, nil
}

func (ss *Session) ReceiveOpen() error {
	openMessage, err := ss.parseOpenMessage()
	if err != nil {
		ss.Logger.Error("Failed to parse OPEN message", zap.Error(err), zap.String("peer-addr", ss.PeerAddr.String()))
		return err
	}

	ss.PCCCapabilities = pcep.PolaCapability(openMessage.OpenObject.Caps)

	// H-PCE Capability processing
	if ss.Mode == ModeParentPCE || (ss.Mode == ModeChildPCE && ss.SessionType == SessionTypeHPCEP) {
		if err := ss.processHPCECapabilities(openMessage.OpenObject.Caps); err != nil {
			ss.Logger.Error("Failed to process H-PCE capabilities", zap.Error(err), zap.String("session-type", string(ss.Mode)))
			return err
		}
		ss.Logger.Debug("H-PCE capabilities processed successfully")
	}

	// pccType detection
	// * FRRouting cannot be detected from the open message, so it is treated as an RFC compliant
	ss.PCCType = pcep.DeterminePccType(ss.PCCCapabilities)
	ss.Logger.Debug("Determine PCC Type", zap.Int("pcc-type", int(ss.PCCType)))
	ss.KeepAlive = openMessage.OpenObject.Keepalive

	return nil
}

// processHPCECapabilities processes H-PCE Capability TLV and Domain-ID TLV from received OPEN message
func (ss *Session) processHPCECapabilities(caps []pcep.CapabilityInterface) error {
	var hpceCapabilityTLV *pcep.HPCECapability
	var domainIDTLV *pcep.DomainID

	// Extract H-PCE Capability and Domain-ID TLV from capabilities
	for _, cap := range caps {
		switch tlv := cap.(type) {
		case *pcep.HPCECapability:
			hpceCapabilityTLV = tlv
		case *pcep.DomainID:
			domainIDTLV = tlv
		}
	}

	// Validate H-PCE Capability presence
	if hpceCapabilityTLV == nil {
		return fmt.Errorf("H-PCE Capability TLV not found in OPEN message for H-PCE session")
	}

	// Process based on session type and H-PCE capability
	switch ss.Mode {
	case ModeParentPCE:
		// This is Parent PCE receiving OPEN from Child PCE
		if hpceCapabilityTLV.ParentPCERequest {
			ss.Logger.Warn("Child PCE sent H-PCE Capability with P-bit=1, expected P-bit=0")
			return fmt.Errorf("invalid H-PCE Capability: Child PCE should set P-bit=0")
		}
		hpceCapabilityTLV.ParentPCERequest = true
		ss.PCCCapabilities = append(ss.PCCCapabilities, hpceCapabilityTLV)

		// Extract peer domain ID if present
		if domainIDTLV != nil {
			peerDomainID := domainIDTLV.GetDomainIDAsUint32()
			ss.PeerDomainID = peerDomainID
		}
	case ModeChildPCE:
		if ss.SessionType == SessionTypeHPCEP {
			// This is Child PCE receiving OPEN response from Parent PCE
			if !hpceCapabilityTLV.ParentPCERequest {
				ss.Logger.Warn("Parent PCE sent H-PCE Capability with P-bit=0, expected P-bit=1")
				return fmt.Errorf("invalid H-PCE Capability: Parent PCE should set P-bit=1")
			}
			hpceCapabilityTLV.ParentPCERequest = false
			ss.PCCCapabilities = append(ss.PCCCapabilities, hpceCapabilityTLV)
		}
	default:
		return fmt.Errorf("H-PCE capability processing called for non-H-PCE session type: %s", ss.Mode)
	}

	return nil
}

func (ss *Session) SendKeepalive() error {
	keepaliveMessage, err := pcep.NewKeepaliveMessage()
	if err != nil {
		return err
	}
	ss.Logger.Debug("Send Keepalive Message")
	return ss.sendPCEPMessage(keepaliveMessage)
}

func (ss *Session) SendClose(reason pcep.CloseReason) error {
	closeMessage, err := pcep.NewCloseMessage(reason)
	if err != nil {
		return err
	}
	byteCloseMessage := closeMessage.Serialize()

	ss.Logger.Debug("Send Close Message",
		zap.Uint8("reason", uint8(closeMessage.CloseObject.Reason)),
		zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
	if _, err := ss.TCPConn.Write(byteCloseMessage); err != nil {
		return err
	}
	return nil
}

func (ss *Session) ReceivePCEPMessage() error {
	for {
		commonHeader, err := ss.readCommonHeader()
		if err != nil {
			return err
		}
		// wait TCP reassembly packet
		time.Sleep(10 * time.Millisecond)

		switch commonHeader.MessageType {
		case pcep.MessageTypeKeepalive:
			ss.Logger.Debug("Received Keepalive")
		case pcep.MessageTypeReport:
			err = ss.handlePCRpt(commonHeader.MessageLength)
			if err != nil {
				return err
			}
		case pcep.MessageTypeLSPInitReq:
			err = ss.handlePCInitiate(commonHeader.MessageLength)
			if err != nil {
				return err
			}
		case pcep.MessageTypeUpdate:
			err = ss.handlePCUpdate(commonHeader.MessageLength)
			if err != nil {
				return err
			}
		// case pcep.MessageTypePcreq:
		// 	// H-PCE: Handle PCReq messages (for interdomain path computation)
		// 	err = ss.handlePCReq(commonHeader.MessageLength)
		// 	if err != nil {
		// 		return err
		// 	}
		// case pcep.MessageTypePcmRep:
		// 	// H-PCE: Handle PCRep messages (for interdomain path computation)
		// 	err = ss.handlePCRep(commonHeader.MessageLength)
		// 	if err != nil {
		// 		return err
		// 	}
		case pcep.MessageTypeError:
			bytePCErrMessageBody := make([]uint8, commonHeader.MessageLength-pcep.CommonHeaderLength)
			if _, err := ss.TCPConn.Read(bytePCErrMessageBody); err != nil {
				return err
			}
			pcerrMessage := &pcep.PCErrMessage{}
			if err := pcerrMessage.DecodeFromBytes(bytePCErrMessageBody); err != nil {
				return err
			}

			ss.Logger.Debug("Received PCErr",
				zap.Uint8("error-Type", pcerrMessage.PCEPErrorObject.ErrorType),
				zap.Uint8("error-value", pcerrMessage.PCEPErrorObject.ErrorValue),
				zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))
		case pcep.MessageTypeClose:
			byteCloseMessageBody := make([]uint8, commonHeader.MessageLength-pcep.CommonHeaderLength)
			if _, err := ss.TCPConn.Read(byteCloseMessageBody); err != nil {
				return err
			}
			closeMessage := &pcep.CloseMessage{}
			if err := closeMessage.DecodeFromBytes(byteCloseMessageBody); err != nil {
				return err
			}
			ss.Logger.Debug("Received Close",
				zap.String("reason", closeMessage.CloseObject.Reason.String()),
				zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
			// Close session if get Close Message
			return nil
		default:
			ss.Logger.Debug("Received unsupported MessageType",
				zap.String("MessageType", commonHeader.MessageType.String()))
		}
	}
}

func (ss *Session) readCommonHeader() (*pcep.CommonHeader, error) {
	commonHeaderBytes := make([]uint8, pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(commonHeaderBytes); err != nil {
		return nil, err
	}

	commonHeader := &pcep.CommonHeader{}
	if err := commonHeader.DecodeFromBytes(commonHeaderBytes); err != nil {
		return nil, err
	}

	return commonHeader, nil
}

func (ss *Session) handlePCRpt(length uint16) error {
	ss.Logger.Debug("Received PCRpt Message")

	messageBodyBytes := make([]uint8, length-pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(messageBodyBytes); err != nil {
		return err
	}

	message := pcep.NewPCRptMessage()
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		return err
	}

	for _, sr := range message.StateReports {
		// synchronization
		if sr.LSPObject.SFlag {
			ss.Logger.Debug("Synchronize SR Policy information", zap.Any("Message", message))
			ss.RegisterSRPolicy(*sr)
		} else if !sr.LSPObject.SFlag {
			switch {
			// finish synchronization
			case sr.LSPObject.PlspID == 0:
				ss.Logger.Debug("Finish PCRpt state synchronization")
				ss.IsSynced = true
			// response to request from PCE
			case sr.SrpObject.SrpID != 0:
				ss.Logger.Debug("Finish Stateful PCE request", zap.Uint32("srpID", sr.SrpObject.SrpID))
				if sr.LSPObject.RFlag {
					ss.DeleteSRPolicy(*sr)
				} else {
					ss.RegisterSRPolicy(*sr)
				}
			// receive SR Policy with PLSP-ID
			case sr.LSPObject.PlspID != 0:
				ss.Logger.Debug("Received SR Policy", zap.Uint32("plspID", sr.LSPObject.PlspID))
				computedSegmentList, err := ss.computePathFromTED(*sr)
				if err != nil {
					ss.Logger.Error("Failed to compute path from TED", zap.Error(err))
					return err
				}
				sr.EroObject = createEroFromSegmentList(computedSegmentList)

				ss.RegisterSRPolicy(*sr)

				if policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID); found {
					ss.SendPCUpdate(*policy)
				}
			default:
				if sr.LSPObject.RFlag {
					ss.DeleteSRPolicy(*sr)
				} else {
					ss.RegisterSRPolicy(*sr)
				}
			}
		}
	}
	return nil
}

func (ss *Session) computePathFromTED(sr pcep.StateReport) ([]table.Segment, error) {
	if ss.TED == nil {
		return nil, errors.New("TED not available")
	}

	srcRouterID, dstRouterID, err := ss.extractSrcDstRouterIDs(sr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract router IDs: %w", err)
	}

	asn, err := ss.extractASN(srcRouterID)
	if err != nil {
		ss.Logger.Error("Could not determine ASN", zap.Error(err))
	}

	metricType := ss.selectMetricType(sr)

	ss.Logger.Debug("Computed CSPF parameters",
		zap.String("srcRouterID", srcRouterID),
		zap.String("dstRouterID", dstRouterID),
		zap.Uint32("asn", asn),
		zap.String("metricType", metricType.String()))

	segmentList, err := cspf.Cspf(srcRouterID, dstRouterID, asn, metricType, ss.TED)
	if err != nil {
		return nil, fmt.Errorf("CSPF computation failed: %w", err)
	}

	return segmentList, nil
}

func (ss *Session) extractSrcDstRouterIDs(sr pcep.StateReport) (string, string, error) {
	var srcAddr, dstAddr netip.Addr

	if sr.LSPObject.SrcAddr.IsValid() {
		srcAddr = sr.LSPObject.SrcAddr
	}
	if sr.LSPObject.DstAddr.IsValid() {
		dstAddr = sr.LSPObject.DstAddr
	}

	if !srcAddr.IsValid() || !dstAddr.IsValid() {
		return "", "", errors.New("could not extract valid source and destination addresses")
	}

	srcRouterID, err := ss.findRouterIDFromAddress(srcAddr)
	if err != nil {
		return "", "", fmt.Errorf("cannot find source router ID for %s: %w", srcAddr, err)
	}

	dstRouterID, err := ss.findRouterIDFromAddress(dstAddr)
	if err != nil {
		return "", "", fmt.Errorf("cannot find destination router ID for %s: %w", dstAddr, err)
	}

	return srcRouterID, dstRouterID, nil
}

func (ss *Session) findRouterIDFromAddress(addr netip.Addr) (string, error) {
	for _, nodes := range ss.TED.Nodes {
		for routerID, node := range nodes {
			for _, prefix := range node.Prefixes {
				if prefix.Prefix.Contains(addr) {
					return routerID, nil
				}
			}
			if node.RouterID == addr.String() {
				return routerID, nil
			}
		}
	}
	return "", fmt.Errorf("address %s not found in TED", addr)
}

func (ss *Session) extractASN(srcRouterID string) (uint32, error) {
	for asn, nodes := range ss.TED.Nodes {
		if _, exists := nodes[srcRouterID]; exists {
			return asn, nil
		}
	}
	return 0, fmt.Errorf("ASN not found for router %s", srcRouterID)
}

func (ss *Session) selectMetricType(sr pcep.StateReport) table.MetricType {
	if len(sr.MetricObjects) > 0 {
		switch sr.MetricObjects[0].MetricType {
		case 1:
			return table.IGPMetric
		case 2:
			return table.TEMetric
		case 3:
			return table.DelayMetric
		case 4:
			return table.HopcountMetric
		default:
			return table.TEMetric
		}
	}

	switch ss.PCCType {
	case pcep.CiscoLegacy:
		return table.TEMetric
	case pcep.JuniperLegacy:
		return table.IGPMetric
	default:
		return table.TEMetric
	}
}

func createEroFromSegmentList(segmentList []table.Segment) *pcep.EroObject {
	eroObject := &pcep.EroObject{
		ObjectType:    pcep.ObjectTypeEROExplicitRoute,
		EroSubobjects: make([]pcep.EroSubobject, 0),
	}

	for _, segment := range segmentList {
		switch seg := segment.(type) {
		case table.SegmentSRMPLS:
			subobj, err := pcep.NewSREroSubObject(seg)
			if err == nil {
				eroObject.EroSubobjects = append(eroObject.EroSubobjects, subobj)
			}
		case table.SegmentSRv6:
			subobj, err := pcep.NewSRv6EroSubObject(seg)
			if err == nil {
				eroObject.EroSubobjects = append(eroObject.EroSubobjects, subobj)
			}
		}
	}

	return eroObject
}

func (ss *Session) RequestAllSRPolicyDeleted() error {
	var srPolicy table.SRPolicy
	return ss.SendPCInitiate(srPolicy, true)
}

func (ss *Session) RequestSRPolicyDeleted(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, true)
}

func (ss *Session) RequestSRPolicyCreated(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, false)
}

func (ss *Session) SendOpen() error {
	openMessage, err := pcep.NewOpenMessage(ss.SessionID, ss.KeepAlive, ss.PCCCapabilities)
	if err != nil {
		return err
	}
	ss.Logger.Debug("Send Open Message")
	return ss.sendPCEPMessage(openMessage)
}

func (ss *Session) SendOpenAsClient() error {
	ss.PCCCapabilities = pcep.PolaPCEPClientCapability()
	if ss.Mode == ModeChildPCE {
		hpceCapabilityTLV := pcep.NewHPCECapability(false)
		ss.PCCCapabilities = append(ss.PCCCapabilities, hpceCapabilityTLV)
		if ss.LocalDomainID > 0 {
			domainIDTLV := pcep.NewDomainID(pcep.DomainType4ByteAS, ss.LocalDomainID)
			ss.PCCCapabilities = append(ss.PCCCapabilities, domainIDTLV)

			ss.Logger.Debug("Added Domain-ID TLV to H-PCE OPEN message", zap.Uint32("local-domain-id", ss.LocalDomainID), zap.String("domain-type", "4ByteAS"))
		}
	}

	openMessage, err := pcep.NewOpenMessage(ss.SessionID, ss.KeepAlive, ss.PCCCapabilities)
	if err != nil {
		return err
	}
	openMessage.OpenObject.Deadtime = 120
	openMessage.OpenObject.Keepalive = 30
	ss.KeepAlive = openMessage.OpenObject.Keepalive
	openMessage.OpenObject.Sid = 0
	ss.Logger.Debug("Send Open Message")
	return ss.sendPCEPMessage(openMessage)
}

func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy, lspDelete bool) error {
	pcinitiateMessage, err := pcep.NewPCInitiateMessage(ss.SRPIDHead, srPolicy.Name, lspDelete, srPolicy.PlspID, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(ss.PCCType))
	if err != nil {
		return err
	}
	ss.Logger.Debug("Send PCInitiate Message")
	err = ss.sendPCEPMessage(pcinitiateMessage)
	if err == nil {
		ss.SRPIDHead++
	}
	return err
}

func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(ss.SRPIDHead, srPolicy.Name, srPolicy.PlspID, srPolicy.SegmentList)
	if err != nil {
		return err
	}
	ss.Logger.Debug("Send Update Message")
	err = ss.sendPCEPMessage(pcupdateMessage)
	if err == nil {
		ss.SRPIDHead++
	}
	return err
}

func (ss *Session) handlePCInitiate(length uint16) error {
	messageBodyBytes := make([]uint8, length-pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(messageBodyBytes); err != nil {
		return err
	}

	message := &pcep.PCInitiateMessage{}
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		ss.Logger.Warn("Failed to decode PCInitiate message", zap.Error(err))
		return err
	}

	// Send PCRpt response to PCInitiate
	return ss.SendPCRpt(message)
}

func (ss *Session) handlePCUpdate(length uint16) error {
	ss.Logger.Debug("Received PCUpdate Message")

	messageBodyBytes := make([]uint8, length-pcep.CommonHeaderLength)
	if _, err := ss.TCPConn.Read(messageBodyBytes); err != nil {
		return err
	}

	message := &pcep.PCUpdMessage{}
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		ss.Logger.Warn("Failed to decode PCUpdate message", zap.Error(err))
		return err
	}

	// Send PCRpt response to PCUpdate
	return ss.SendPCRpt(message)
}

// // handleInterDomainPCReq handles inter-domain path computation requests (Child PCE)
// func (ss *Session) handlePCReq(length uint16) error {
// 	// TODO: Implement inter-domain PCReq handling
// 	ss.Logger.Debug("Processing inter-domain PCReq from Parent PCE")
// 	return nil
// }

// // handleInterDomainPCRep handles inter-domain path computation replies (Parent PCE)
// func (ss *Session) handlePCRep(length uint16) error {
// 	// TODO: Implement inter-domain PCRep handling
// 	ss.Logger.Debug("Processing inter-domain PCRep from Child PCE")
// 	return nil
// }

func (ss *Session) SendPCRpt(message interface{}) error {
	pcrptMessage := pcep.NewPCRptMessage()
	var stateReport *pcep.StateReport

	switch msg := message.(type) {
	case *pcep.PCInitiateMessage:
		if msg.LSPObject.RFlag {
			// LSP deletion request
			ss.Logger.Debug("Processing LSP deletion request", zap.Uint32("plspID", msg.LSPObject.PlspID))

			stateReport = &pcep.StateReport{
				SrpObject: &pcep.SrpObject{
					SrpID: msg.SrpObject.SrpID,
					TLVs: []pcep.TLVInterface{
						&pcep.PathSetupType{
							PathSetupType: pcep.PathSetupTypeSRv6TE,
						},
					},
				},
				LSPObject: &pcep.LSPObject{
					PlspID: msg.LSPObject.PlspID,
					Name:   msg.LSPObject.Name,
					SFlag:  false,
					DFlag:  true,
					CFlag:  false,
					AFlag:  false,
					RFlag:  true, // Mark for removal
					OFlag:  0,
					TLVs: []pcep.TLVInterface{
						&pcep.SymbolicPathName{
							Name: msg.LSPObject.Name,
						},
					},
				},
			}

			// Delete SR Policy from local storage
			ss.DeleteSRPolicy(*stateReport)

			ss.Logger.Debug("Send PCRpt Response to PCInitiate (Delete)",
				zap.Uint32("srpID", msg.SrpObject.SrpID),
				zap.Uint32("plspID", stateReport.LSPObject.PlspID))
		} else {
			// LSP creation request
			ss.Logger.Debug("Processing LSP creation request", zap.String("name", msg.LSPObject.Name))

			// Create state report based on PCInitiate request
			stateReport = &pcep.StateReport{
				SrpObject: &pcep.SrpObject{
					SrpID: msg.SrpObject.SrpID, // Echo back the SRP-ID from PCInitiate
					TLVs: []pcep.TLVInterface{
						&pcep.PathSetupType{
							PathSetupType: pcep.PathSetupTypeSRv6TE,
						},
					},
				},
				LSPObject: &pcep.LSPObject{
					PlspID: ss.generatePLSPID(), // Generate new PLSP-ID for the LSP
					Name:   msg.LSPObject.Name,
					SFlag:  false, // Not in sync state
					DFlag:  true,  // PCE can delegate
					CFlag:  true,  // LSP was created
					AFlag:  true,  // LSP is administratively active
					RFlag:  false, // LSP is not being removed
					OFlag:  1,     // LSP is operationally active
					TLVs: []pcep.TLVInterface{
						&pcep.SymbolicPathName{
							Name: msg.LSPObject.Name,
						},
					},
				},
				EroObject:         msg.EroObject,         // Echo back the ERO from PCInitiate
				AssociationObject: msg.AssociationObject, // Echo back Association if present
			}

			// Set source and destination addresses from Endpoints object
			if msg.EndpointsObject != nil {
				stateReport.LSPObject.SrcAddr = msg.EndpointsObject.SrcAddr
				stateReport.LSPObject.DstAddr = msg.EndpointsObject.DstAddr
			}

			// Register SR Policy to local storage
			ss.RegisterSRPolicy(*stateReport)

			ss.Logger.Debug("Send PCRpt Response to PCInitiate (Create)",
				zap.Uint32("srpID", msg.SrpObject.SrpID),
				zap.Uint32("plspID", stateReport.LSPObject.PlspID))
		}

	case *pcep.PCUpdMessage:
		// Create state report based on PCUpdate request
		stateReport = &pcep.StateReport{
			SrpObject: &pcep.SrpObject{
				SrpID: msg.SrpObject.SrpID, // Echo back the SRP-ID from PCUpdate
				TLVs: []pcep.TLVInterface{
					&pcep.PathSetupType{
						PathSetupType: pcep.PathSetupTypeSRv6TE,
					},
				},
			},
			LSPObject: &pcep.LSPObject{
				PlspID: msg.LSPObject.PlspID, // Use existing PLSP-ID from PCUpdate
				Name:   msg.LSPObject.Name,
				SFlag:  false, // Not in sync state
				DFlag:  true,  // PCE can delegate
				CFlag:  true,  // LSP was not created (existing LSP)
				AFlag:  true,  // LSP is administratively active
				RFlag:  false, // LSP is not being removed
				OFlag:  1,     // LSP is operationally active
				TLVs: []pcep.TLVInterface{
					&pcep.SymbolicPathName{
						Name: msg.LSPObject.Name,
					},
				},
			},
			EroObject: msg.EroObject, // Echo back the ERO from PCUpdate
		}

		ss.Logger.Debug("Send PCRpt Response to PCUpdate",
			zap.Uint32("srpID", msg.SrpObject.SrpID),
			zap.Uint32("plspID", stateReport.LSPObject.PlspID))

	default:
		return fmt.Errorf("unsupported message type for PCRpt response: %T", message)
	}

	pcrptMessage.StateReports = append(pcrptMessage.StateReports, stateReport)
	return ss.sendPCEPMessage(pcrptMessage)
}

func (ss *Session) generatePLSPID() uint32 {
	// Simple PLSP-ID generation - start from 1 and increment
	// In a real implementation, this should be more sophisticated
	maxPLSPID := uint32(0)
	for _, policy := range ss.SRPolicies {
		if policy.PlspID > maxPLSPID {
			maxPLSPID = policy.PlspID
		}
	}
	return maxPLSPID + 1
}

func (ss *Session) SendSyncCompletion() error {
	// Create PCRpt message with PLSP-ID=0 to indicate sync completion
	pcrptMessage := pcep.NewPCRptMessage()

	// Create state report with PLSP-ID=0 to indicate end of synchronization
	stateReport := &pcep.StateReport{
		LSPObject: &pcep.LSPObject{
			PlspID: 0,     // PLSP-ID 0 indicates end of synchronization
			Name:   "",    // Empty name for sync completion
			SFlag:  false, // S-flag false for sync completion
			DFlag:  false,
			CFlag:  false,
			AFlag:  false,
			RFlag:  false,
			OFlag:  0,
		},
		EroObject: &pcep.EroObject{
			ObjectType:    pcep.ObjectTypeEROExplicitRoute,
			EroSubobjects: []pcep.EroSubobject{}, // Empty ERO for sync completion
		},
	}

	pcrptMessage.StateReports = append(pcrptMessage.StateReports, stateReport)

	ss.Logger.Debug("Send PCRpt Sync Completion Message")
	return ss.sendPCEPMessage(pcrptMessage)
}

func (ss *Session) RegisterSRPolicy(sr pcep.StateReport) {
	var color uint32 = 0      // Default color value (RFC does not specify a default)
	var preference uint32 = 0 // Default preference value (RFC does not specify a default)

	if ss.PCCType == pcep.CiscoLegacy {
		// In Cisco legacy mode, get color and preference from Vendor Information Object
		color = sr.VendorInformationObject.Color()
		preference = sr.VendorInformationObject.Preference()
	} else {
		// TODO: Move hasColorCapability to Session struct
		hasColorCapability := false
		for _, cap := range ss.PCCCapabilities {
			if statefulCap, ok := cap.(*pcep.StatefulPCECapability); ok {
				if statefulCap.ColorCapability {
					hasColorCapability = true
					break
				}
			}
		}

		// SR Policy Association color takes precedence over LSP Object Color TLV
		// Ref: https://datatracker.ietf.org/doc/draft-ietf-pce-pcep-color/12/ Section 2
		if sr.AssociationObject.Color() != 0 {
			color = sr.AssociationObject.Color()
		} else if hasColorCapability {
			color = sr.LSPObject.Color()
		}

		preference = sr.AssociationObject.Preference()
	}

	lspID := sr.LSPObject.LSPID

	var state table.PolicyState
	switch sr.LSPObject.OFlag {
	case uint8(0x00):
		state = table.PolicyDown
	case uint8(0x01):
		state = table.PolicyUp
	case uint8(0x02):
		state = table.PolicyActive
	default:
		state = table.PolicyUnknown
	}

	if p, ok := ss.SearchSRPolicy(sr.LSPObject.PlspID); ok {
		// update
		// If the LSP ID is old, it is not the latest data update.
		if p.LSPID <= lspID {
			p.Update(
				table.PolicyDiff{
					Name:        &sr.LSPObject.Name,
					Color:       &color,
					Preference:  &preference,
					SegmentList: sr.EroObject.ToSegmentList(),
					LSPID:       lspID,
					State:       state,
				},
			)
		}
	} else {
		// create
		var src, dst netip.Addr
		if src = sr.LSPObject.SrcAddr; !src.IsValid() {
			src = sr.AssociationObject.AssocSrc
		}
		if dst = sr.LSPObject.DstAddr; !dst.IsValid() {
			dst = sr.AssociationObject.Endpoint()
		}
		p := table.NewSRPolicy(
			sr.LSPObject.PlspID,
			sr.LSPObject.Name,
			sr.EroObject.ToSegmentList(),
			src,
			dst,
			color,
			preference,
			lspID,
			state,
		)
		ss.SRPolicies = append(ss.SRPolicies, p)
	}
}

func (ss *Session) DeleteSRPolicy(sr pcep.StateReport) {
	lspID := sr.LSPObject.LSPID
	for i, v := range ss.SRPolicies {
		// If the LSP ID is old, it is not the latest data update.
		if v.PlspID == sr.LSPObject.PlspID && v.LSPID <= lspID {
			ss.SRPolicies[i] = ss.SRPolicies[len(ss.SRPolicies)-1]
			ss.SRPolicies = ss.SRPolicies[:len(ss.SRPolicies)-1]
			break
		}
	}
}

func (ss *Session) SearchSRPolicy(plspID uint32) (*table.SRPolicy, bool) {
	for _, v := range ss.SRPolicies {
		if v.PlspID == plspID {
			return v, true
		}
	}
	return nil, false
}

// SearchPlspID returns the PLSP-ID of a registered SR Policy, along with a boolean value indicating if it was found.
func (ss *Session) SearchPlspID(color uint32, endpoint netip.Addr) (uint32, bool) {
	for _, v := range ss.SRPolicies {
		if v.Color == color && v.DstAddr == endpoint {
			return v.PlspID, true
		}
	}
	return 0, false
}
