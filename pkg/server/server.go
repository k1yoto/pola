// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"time"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	"github.com/nttcom/pola/internal/pkg/table"
)

// PCEMode represents all PCE operation modes (unified)
type PCEMode string

const (
	ModePCC       PCEMode = "pcc"
	ModePCE       PCEMode = "pce"
	ModeChildPCE  PCEMode = "c-pce"
	ModeParentPCE PCEMode = "p-pce"
)

type Server struct {
	Mode        PCEMode
	SessionList []*Session
	TED         *table.LsTED
	Logger      *zap.Logger
	DomainID    uint32 // For H-PCE modes
}

// CommonOptions represents unified options for all PCE modes
type CommonOptions struct {
	Mode           PCEMode
	PCEPServerAddr string // For server modes (PCE, P-PCE)
	PCEPServerPort string // For server modes (PCE, P-PCE)
	PCEPClientAddr string // For client modes (PCC, C-PCE)
	PCEPClientPort string // For client modes (PCC, C-PCE)
	GRPCAddr       string // gRPC server address (all modes)
	GRPCPort       string // gRPC server port (all modes)
	TEDEnable      bool   // TED enable flag (PCE, P-PCE, C-PCE)
	USidMode       bool   // uSID mode flag (all modes)
	DomainID       uint32
}

// NewPCEServer creates a unified PCE server for all modes
func NewPCEServer(o *CommonOptions, logger *zap.Logger, tedElemsChan chan []table.TEDElem) Error {
	s := &Server{
		Logger: logger,
		Mode:   o.Mode,
	}

	// Initialize mode-specific fields
	switch o.Mode {
	case ModeParentPCE, ModeChildPCE:
		s.DomainID = o.DomainID
	}

	// TED initialization for server modes
	if o.TEDEnable && (o.Mode == ModePCE || o.Mode == ModeParentPCE || o.Mode == ModeChildPCE) {
		s.TED = &table.LsTED{
			ID:    1,
			Nodes: map[uint32]map[string]*table.LsNode{},
		}

		// Start TED update goroutine
		go func() {
			for {
				tedElems := <-tedElemsChan
				ted := &table.LsTED{
					ID:    s.TED.ID,
					Nodes: map[uint32]map[string]*table.LsNode{},
				}
				ted.Update(tedElems)
				s.TED = ted
				logger.Debug("Update TED")

				// Child PCE: Generate abstracted TED for Parent PCE
				if o.Mode == ModeChildPCE {
					s.ExtractAbstractedTED(ted)
				}
			}
		}()
	}

	// Start server/client based on mode
	errChan := make(chan Error)

	// Start PCEP server for server modes
	if o.Mode == ModePCE || o.Mode == ModeParentPCE || o.Mode == ModeChildPCE {
		go func() {
			if err := s.Serve(o.PCEPServerAddr, o.PCEPServerPort, o.USidMode); err != nil {
				errChan <- Error{
					Server: "pcep-server",
					Error:  err,
				}
			}
		}()
	}

	// Start PCEP client for client modes
	if o.Mode == ModePCC || o.Mode == ModeChildPCE {
		go func() {
			// Unify Connect and ConnectToParentPCE
			if err := s.Connect(o.PCEPClientAddr, o.PCEPClientPort, o.USidMode); err != nil {
				errChan <- Error{
					Server: "pcep-client",
					Error:  err,
				}
			}
		}()
	}

	// Start gRPC server for all modes
	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer, o.USidMode, logger)
		if err := apiServer.Serve(o.GRPCAddr, o.GRPCPort); err != nil {
			errChan <- Error{
				Server: "grpc",
				Error:  err,
			}
		}
	}()

	serverError := <-errChan
	logger.Error("Server encountered an error", zap.String("server", serverError.Server), zap.String("mode", string(o.Mode)), zap.Error(serverError.Error))
	return serverError
}

func (s *Server) Serve(address string, port string, usidMode bool) error {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("failed to parse address %s: %w", address, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("failed to convert port %s: %w", port, err)
	}
	if p > math.MaxUint16 {
		return errors.New("invalid PCEP listen port")
	}
	localAddr := netip.AddrPortFrom(a, uint16(p))

	s.Logger.Info("start listening on PCEP port", zap.String("address", localAddr.String()))
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on PCEP port %s: %w", localAddr.String(), err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			s.Logger.Warn("failed to close PCEP listener", zap.Error(err))
		}
	}()

	sessionID := uint8(1)
	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("failed to accept TCP connection: %w", err)
		}
		peerAddrPort, err := netip.ParseAddrPort(tcpConn.RemoteAddr().String())
		if err != nil {
			return fmt.Errorf("failed to parse remote address %s: %w", tcpConn.RemoteAddr().String(), err)
		}

		var ss *Session
		if s.Mode == ModeParentPCE {
			ss = NewSession(sessionID, peerAddrPort.Addr(), tcpConn, s.Logger, s.TED, s.Mode, SessionTypeHPCEP, s.DomainID)
		} else {
			ss = NewSession(sessionID, peerAddrPort.Addr(), tcpConn, s.Logger, s.TED, s.Mode, SessionTypePCEP, s.DomainID)
		}
		s.SessionList = append(s.SessionList, ss)
		go func() {
			ss.Established()
			s.CloseSession(ss)
			ss.Logger.Info("close PCEP session")
		}()
		sessionID++
	}
}

// connectToParentPCE establishes connection from Child PCE to Parent PCE
func (s *Server) Connect(address string, port string, usidMode bool) error {
	for {
		a, err := netip.ParseAddr(address)
		if err != nil {
			s.Logger.Error("Failed to parse Parent PCE address", zap.String("address", address), zap.Error(err))
			time.Sleep(30 * time.Second)
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p > math.MaxUint16 {
			s.Logger.Error("Invalid Parent PCE port", zap.String("port", port), zap.Error(err))
			time.Sleep(30 * time.Second)
			continue
		}
		ap := netip.AddrPortFrom(a, uint16(p))
		remoteAddr := net.TCPAddrFromAddrPort(ap)
		tcpConn, err := net.DialTCP("tcp", nil, remoteAddr)
		if err != nil {
			s.Logger.Warn("Failed to connect to Parent PCE, retrying...", zap.String("parent-addr", ap.String()), zap.Error(err))
			time.Sleep(30 * time.Second)
			continue
		}

		sessionID := uint8(len(s.SessionList) + 1)
		var ss *Session
		if s.Mode == ModeChildPCE {
			ss = NewSession(sessionID, a, tcpConn, s.Logger, s.TED, s.Mode, SessionTypeHPCEP, s.DomainID)
		} else {
			ss = NewSession(sessionID, a, tcpConn, s.Logger, s.TED, s.Mode, SessionTypePCEP, s.DomainID)
		}
		s.SessionList = append(s.SessionList, ss)

		s.Logger.Info("Successfully connected to PCE, starting PCE session")
		go func() {
			// Unify EstablishedAsPCC and EstablishedAsChildPCE
			ss.Established()
			s.CloseSession(ss)
			s.Logger.Info("PCE session closed")
		}()

		break
	}
	return nil
}

func (s *Server) CloseSession(session *Session) {
	if err := session.TCPConn.Close(); err != nil {
		s.Logger.Warn("failed to close TCP connection", zap.Error(err))
	}

	// Remove Session List
	for i, v := range s.SessionList {
		if v.SessionID == session.SessionID {
			s.SessionList[i] = s.SessionList[len(s.SessionList)-1]
			s.SessionList = s.SessionList[:len(s.SessionList)-1]
			break
		}
	}
}

// SearchSession returns a struct pointer of (Synced) session.
// If not exist, return nil
func (s *Server) SearchSession(peerAddr netip.Addr, onlySynced bool) *Session {
	for _, pcepSession := range s.SessionList {
		if pcepSession.PeerAddr == peerAddr {
			if !onlySynced || pcepSession.IsSynced {
				return pcepSession
			}
		}
	}
	return nil
}

// SRPolicies returns a map of registered SR Policy with key sessionAddr
func (s *Server) SRPolicies() map[netip.Addr][]*table.SRPolicy {
	srPolicies := make(map[netip.Addr][]*table.SRPolicy)
	for _, ss := range s.SessionList {
		if ss.IsSynced {
			srPolicies[ss.PeerAddr] = ss.SRPolicies
		}
	}
	return srPolicies
}

// // H-PCE related methods

// generate abstracted TED information from local TED
func (s *Server) ExtractAbstractedTED(localTED *table.LsTED) {
	return
}
