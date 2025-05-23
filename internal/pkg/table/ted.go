// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

type LsTed struct {
	ID    int
	Nodes map[uint32]map[string]*LsNode // { ASN1: {"NodeID1": node1, "NodeID2": node2}, ASN2: {"NodeID3": node3, "NodeID4": node4}}
}

func (ted *LsTed) Update(tedElems []TedElem) {
	// check Before State Update TED
	fmt.Printf("Before State Update TED: %v\n", ted)
	for _, tedElem := range tedElems {
		tedElem.UpdateTed(ted)
	}
	// check After State Update TED
	fmt.Printf("After State Update TED: %v\n", ted)
	ted.Print()
}

func (ted *LsTed) Print() {
	for _, nodes := range ted.Nodes {
		nodeCnt := 1
		for nodeID, node := range nodes {
			fmt.Printf("Node: %d\n", nodeCnt)
			fmt.Printf("  %s\n", nodeID)
			fmt.Printf("  Hostname: %s\n", node.Hostname)
			fmt.Printf("  ISIS Area ID: %s\n", node.IsisAreaID)
			fmt.Printf("  SRGB: %d - %d\n", node.SrgbBegin, node.SrgbEnd)
			fmt.Printf("  Prefixes:\n")
			for _, prefix := range node.Prefixes {
				fmt.Printf("    %s\n", prefix.Prefix.String())
				if prefix.SidIndex != 0 {
					fmt.Printf("      index: %d\n", prefix.SidIndex)
				}
			}
			fmt.Printf("  Links:\n")
			for _, link := range node.Links {
				fmt.Printf("    Local: %s Remote: %s\n", link.LocalIP.String(), link.RemoteIP.String())
				fmt.Printf("      RemoteNode: %s\n", link.RemoteNode.RouterID)
				fmt.Printf("      Metrics:\n")
				for _, metric := range link.Metrics {
					fmt.Printf("        %s: %d\n", metric.Type.String(), metric.Value)
				}
				fmt.Printf("      Adj-SID: %d\n", link.AdjSid)
			}
			fmt.Printf("  SRv6 SIDs:\n")
			for _, srv6SID := range node.SRv6SIDs {
				fmt.Printf("    SIDs: %v\n", srv6SID.Sids)
				fmt.Printf("    EndpointBehavior: %d\n", srv6SID.EndpointBehavior)
				fmt.Printf("    MultiTopoIDs: %v\n", srv6SID.MultiTopoIDs)
				fmt.Printf("    ServiceType: %d\n", srv6SID.ServiceType)
				fmt.Printf("    TrafficType: %d\n", srv6SID.TrafficType)
				fmt.Printf("    OpaqueType: %d\n", srv6SID.OpaqueType)
				fmt.Printf("    Value: %v\n", srv6SID.Value)
			}

			nodeCnt++
			fmt.Printf("\n")
		}
	}
}

type TedElem interface {
	UpdateTed(ted *LsTed)
}

type LsNode struct {
	Asn        uint32 // primary key, in MP_REACH_NLRI Attr
	RouterID   string // primary key, in MP_REACH_NLRI Attr
	IsisAreaID string // in BGP-LS Attr
	Hostname   string // in BGP-LS Attr
	SrgbBegin  uint32 // in BGP-LS Attr
	SrgbEnd    uint32 // in BGP-LS Attr
	Links      []*LsLink
	Prefixes   []*LsPrefixV4
	SRv6SIDs   []*LsSrv6SID // for SRv6
}

func NewLsNode(asn uint32, nodeID string) *LsNode {
	return &LsNode{
		Asn:      asn,
		RouterID: nodeID,
	}
}

func (n *LsNode) NodeSegment() (Segment, error) {
	// for SR-MPLS Segment
	for _, prefix := range n.Prefixes {
		if prefix.SidIndex != 0 {
			sid := strconv.Itoa(int(n.SrgbBegin + prefix.SidIndex))
			seg, err := NewSegment(sid)
			if err != nil {
				return nil, err
			}
			return seg, nil
		}
	}
	// TODO: for SRv6 Segment

	return nil, errors.New("node doesn't have a Node SID")
}

func (n *LsNode) LoopbackAddr() (netip.Addr, error) {
	for _, prefix := range n.Prefixes {
		if prefix.SidIndex != 0 {
			return prefix.Prefix.Addr(), nil
		}
	}

	return netip.Addr{}, errors.New("node doesn't have a loopback address")
}

func (n *LsNode) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, n.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if node, ok := nodes[asn][n.RouterID]; ok {
		node.Hostname = n.Hostname
		node.IsisAreaID = n.IsisAreaID
		node.SrgbBegin = n.SrgbBegin
		node.SrgbEnd = n.SrgbEnd
	} else {
		nodes[asn][n.RouterID] = n
	}
}

func (n *LsNode) AddLink(link *LsLink) {
	n.Links = append(n.Links, link)
}

type LsLink struct {
	LocalNode  *LsNode    // Primary key, in MP_REACH_NLRI Attr
	RemoteNode *LsNode    // Primary key, in MP_REACH_NLRI Attr
	LocalIP    netip.Addr // In MP_REACH_NLRI Attr
	RemoteIP   netip.Addr // In MP_REACH_NLRI Attr
	Metrics    []*Metric  // In BGP-LS Attr
	AdjSid     uint32     // In BGP-LS Attr
}

func NewLsLink(localNode *LsNode, remoteNode *LsNode) *LsLink {
	return &LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
	}
}

func (l *LsLink) Metric(metricType MetricType) (uint32, error) {
	for _, metric := range l.Metrics {
		if metric.Type == metricType {
			return metric.Value, nil
		}
	}

	return 0, fmt.Errorf("metric %s not defined", metricType)
}

func (l *LsLink) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, l.LocalNode.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][l.LocalNode.RouterID]; !ok {
		nodes[asn][l.LocalNode.RouterID] = NewLsNode(l.LocalNode.Asn, l.LocalNode.RouterID)
	}

	if _, ok := nodes[l.RemoteNode.Asn][l.RemoteNode.RouterID]; !ok {
		nodes[l.RemoteNode.Asn][l.RemoteNode.RouterID] = NewLsNode(l.RemoteNode.Asn, l.RemoteNode.RouterID)
	}

	l.LocalNode, l.RemoteNode = nodes[asn][l.LocalNode.RouterID], nodes[l.RemoteNode.Asn][l.RemoteNode.RouterID]

	l.LocalNode.AddLink(l)
}

type LsPrefixV4 struct {
	LocalNode *LsNode      // primary key, in MP_REACH_NLRI Attr
	Prefix    netip.Prefix // in MP_REACH_NLRI Attr
	SidIndex  uint32       // in BGP-LS Attr (only for Lo Address Prefix)
}

func NewLsPrefixV4(localNode *LsNode) *LsPrefixV4 {
	return &LsPrefixV4{
		LocalNode: localNode,
	}
}

func (lp *LsPrefixV4) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, lp.LocalNode.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][lp.LocalNode.RouterID]; !ok {
		nodes[asn][lp.LocalNode.RouterID] = NewLsNode(lp.LocalNode.Asn, lp.LocalNode.RouterID)
	}

	localNode := nodes[asn][lp.LocalNode.RouterID]
	for _, pref := range localNode.Prefixes {
		if pref.Prefix.String() == lp.Prefix.String() {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
}

// // LsSrv6SID represents a SRv6 SID
type LsSrv6SID struct {
	LocalNode        *LsNode  // primary key, in MP_REACH_NLRI Attr
	Sids             []string // in LsSrv6SID Attr
	EndpointBehavior uint32   // in srv6EndpointBehavior Attr
	MultiTopoIDs     []uint32 // in LsSrv6SID Attr
	ServiceType      uint32   // in LsSrv6SID Attr
	TrafficType      uint32   // in LsSrv6SID Attr
	OpaqueType       uint32   // in LsSrv6SID Attr
	Value            []byte   // in LsSrv6SID Attr
}

func NewLsSrv6SID(node *LsNode) *LsSrv6SID {
	return &LsSrv6SID{
		LocalNode: node,
	}
}

func (s *LsSrv6SID) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, s.LocalNode.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][s.LocalNode.RouterID]; !ok {
		nodes[asn][s.LocalNode.RouterID] = NewLsNode(s.LocalNode.Asn, s.LocalNode.RouterID)
	}

	s.LocalNode = nodes[asn][s.LocalNode.RouterID]

	s.LocalNode.AddSrv6SID(s)
}

func (n *LsNode) AddSrv6SID(s *LsSrv6SID) {
	n.SRv6SIDs = append(n.SRv6SIDs, s)
}

type Metric struct {
	Type  MetricType
	Value uint32
}

func NewMetric(metricType MetricType, value uint32) *Metric {
	return &Metric{
		Type:  metricType,
		Value: value,
	}
}

type MetricType int

const (
	IGP_METRIC MetricType = iota
	TE_METRIC
	DELAY_METRIC
	HOPCOUNT_METRIC
)

func (m MetricType) String() string {
	switch m {
	case IGP_METRIC:
		return "IGP"
	case TE_METRIC:
		return "TE"
	case DELAY_METRIC:
		return "DELAY"
	case HOPCOUNT_METRIC:
		return "HOPCOUNT"
	default:
		return "Unknown"
	}
}
