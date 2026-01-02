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

type LsTED struct {
	ID    int                           `json:"id"`
	Nodes map[uint32]map[string]*LsNode `json:"nodes"` // { ASN1: {"NodeID1": node1, "NodeID2": node2}, ASN2: {"NodeID3": node3, "NodeID4": node4}}
}

func (ted *LsTED) Update(tedElems []TEDElem) {
	for _, tedElem := range tedElems {
		tedElem.UpdateTED(ted)
	}
}

func (ted *LsTED) Print() {
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
				fmt.Printf("      SRv6 End.X SID:\n")
				fmt.Printf("        EndpointBehavior: %s\n", BehaviorToString(link.Srv6EndXSID.EndpointBehavior))
				fmt.Printf("        SIDs: %v\n", link.Srv6EndXSID.Sids)
				fmt.Printf("        SID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
					link.Srv6EndXSID.Srv6SIDStructure.LocalBlock,
					link.Srv6EndXSID.Srv6SIDStructure.LocalNode,
					link.Srv6EndXSID.Srv6SIDStructure.LocalFunc,
					link.Srv6EndXSID.Srv6SIDStructure.LocalArg)
			}
			fmt.Printf("  SRv6 SIDs:\n")
			for _, srv6SID := range node.SRv6SIDs {
				fmt.Printf("    SIDs: %v\n", srv6SID.Sids)
				fmt.Printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n", srv6SID.SIDStructure.LocalBlock,
					srv6SID.SIDStructure.LocalNode, srv6SID.SIDStructure.LocalFunc, srv6SID.SIDStructure.LocalArg)
				fmt.Printf("    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n", BehaviorToString(srv6SID.EndpointBehavior.Behavior),
					srv6SID.EndpointBehavior.Flags, srv6SID.EndpointBehavior.Algorithm)
				fmt.Printf("    MultiTopoIDs: %v\n", srv6SID.MultiTopoIDs)
				fmt.Printf("    ServiceType: %d\n", srv6SID.ServiceType)
				fmt.Printf("    TrafficType: %d\n", srv6SID.TrafficType)
				fmt.Printf("    OpaqueType: %d\n", srv6SID.OpaqueType)
				fmt.Printf("    Value: 0x%x\n", srv6SID.Value)
				if srv6SID.BGPPeerNodeSID.PeerASN != 0 || srv6SID.BGPPeerNodeSID.PeerBGPID != "" {
					fmt.Printf("    BGP PeerNode SID:\n")
					fmt.Printf("        Flags: %d\n", srv6SID.BGPPeerNodeSID.Flags)
					fmt.Printf("        Weight: %d\n", srv6SID.BGPPeerNodeSID.Weight)
					fmt.Printf("        Peer ASN: %d\n", srv6SID.BGPPeerNodeSID.PeerASN)
					fmt.Printf("        Peer BGP ID: %s\n", srv6SID.BGPPeerNodeSID.PeerBGPID)
				}
			}

			nodeCnt++
			fmt.Printf("\n")
		}
	}
}

type TEDElem interface {
	UpdateTED(ted *LsTED)
}

type LsNode struct {
	ASN        uint32       `json:"asn"`          // primary key, in MP_REACH_NLRI Attr
	RouterID   string       `json:"router_id"`    // primary key, in MP_REACH_NLRI Attr
	IsisAreaID string       `json:"isis_area_id"` // in BGP-LS Attr
	Hostname   string       `json:"hostname"`     // in BGP-LS Attr
	SrgbBegin  uint32       `json:"srgb_begin"`   // in BGP-LS Attr
	SrgbEnd    uint32       `json:"srgb_end"`     // in BGP-LS Attr
	Links      []*LsLink    `json:"links"`
	Prefixes   []*LsPrefix  `json:"prefixes"`
	SRv6SIDs   []*LsSrv6SID `json:"srv6_sids"`
}

func NewLsNode(asn uint32, nodeID string) *LsNode {
	return &LsNode{
		ASN:      asn,
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
	// for SRv6 Segment
	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) > 0 {
			addr, err := netip.ParseAddr(srv6SID.Sids[FirstSIDIndex])
			if err != nil {
				return nil, err
			}
			seg, err := NewSegmentSRv6WithNodeInfo(addr, n)
			if err != nil {
				return nil, err
			}
			return seg, nil
		}
	}

	return nil, errors.New("node doesn't have a Node SID")
}

func (n *LsNode) LoopbackAddr() (netip.Addr, error) {
	for _, prefix := range n.Prefixes {
		if prefix.SidIndex != 0 || prefix.Prefix.Bits() == 128 {
			return prefix.Prefix.Addr(), nil
		}
	}

	return netip.Addr{}, errors.New("node doesn't have a loopback address")
}

func (n *LsNode) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, n.ASN

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
	LocalNode   *LsNode      `json:"-"`             // Primary key, in MP_REACH_NLRI Attr (omit to avoid circular ref)
	RemoteNode  *LsNode      `json:"-"`             // Primary key, in MP_REACH_NLRI Attr (omit to avoid circular ref)
	LocalIP     netip.Addr   `json:"local_ip"`      // In MP_REACH_NLRI Attr
	RemoteIP    netip.Addr   `json:"remote_ip"`     // In MP_REACH_NLRI Attr
	Metrics     []*Metric    `json:"metrics"`       // In BGP-LS Attr
	AdjSid      uint32       `json:"adj_sid"`       // In BGP-LS Attr
	Srv6EndXSID *Srv6EndXSID `json:"srv6_endx_sid"` // In BGP-LS Attr
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

func (l *LsLink) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, l.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][l.LocalNode.RouterID]; !ok {
		nodes[asn][l.LocalNode.RouterID] = NewLsNode(l.LocalNode.ASN, l.LocalNode.RouterID)
	}

	if _, ok := nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID]; !ok {
		nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID] = NewLsNode(l.RemoteNode.ASN, l.RemoteNode.RouterID)
	}

	l.LocalNode, l.RemoteNode = nodes[asn][l.LocalNode.RouterID], nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID]

	l.LocalNode.AddLink(l)
}

type LsPrefix struct {
	LocalNode *LsNode      `json:"-"`         // primary key, in MP_REACH_NLRI Attr (omit to avoid circular ref)
	Prefix    netip.Prefix `json:"prefix"`    // in MP_REACH_NLRI Attr
	SidIndex  uint32       `json:"sid_index"` // in BGP-LS Attr (only for Lo Address Prefix)
}

func NewLsPrefix(localNode *LsNode) *LsPrefix {
	return &LsPrefix{
		LocalNode: localNode,
	}
}

func (lp *LsPrefix) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, lp.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][lp.LocalNode.RouterID]; !ok {
		nodes[asn][lp.LocalNode.RouterID] = NewLsNode(lp.LocalNode.ASN, lp.LocalNode.RouterID)
	}

	localNode := nodes[asn][lp.LocalNode.RouterID]
	for _, pref := range localNode.Prefixes {
		if pref.Prefix.String() == lp.Prefix.String() {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
}

type SIDStructure struct {
	LocalBlock uint8 `json:"local_block"`
	LocalNode  uint8 `json:"local_node"`
	LocalFunc  uint8 `json:"local_func"`
	LocalArg   uint8 `json:"local_arg"`
}

type EndpointBehavior struct {
	Behavior  uint16 `json:"behavior"`
	Flags     uint8  `json:"flags"`
	Algorithm uint8  `json:"algorithm"`
}

type BGPPeerNodeSID struct {
	Flags     uint8  `json:"flags"`
	Weight    uint8  `json:"weight"`
	PeerASN   uint32 `json:"peer_asn"`
	PeerBGPID string `json:"peer_bgp_id"`
}

type LsSrv6SID struct {
	LocalNode        *LsNode          `json:"-"`                 // primary key, in MP_REACH_NLRI Attr (omit to avoid circular ref)
	Sids             []string         `json:"sids"`              // in LsSrv6SID Attr
	EndpointBehavior EndpointBehavior `json:"endpoint_behavior"` // in BGP-LS Attr
	SIDStructure     SIDStructure     `json:"sid_structure"`     // in BGP-LS Attr
	BGPPeerNodeSID   BGPPeerNodeSID   `json:"bgp_peer_node_sid"` // in BGP-LS Attr
	MultiTopoIDs     []uint32         `json:"multi_topo_ids"`    // in LsSrv6SID Attr
	ServiceType      uint32           `json:"service_type"`      // in LsSrv6SID Attr
	TrafficType      uint32           `json:"traffic_type"`      // in LsSrv6SID Attr
	OpaqueType       uint32           `json:"opaque_type"`       // in LsSrv6SID Attr
	Value            []byte           `json:"value"`             // in LsSrv6SID Attr
}

func NewLsSrv6SID(node *LsNode) *LsSrv6SID {
	return &LsSrv6SID{
		LocalNode: node,
	}
}

func (s *LsSrv6SID) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, s.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][s.LocalNode.RouterID]; !ok {
		nodes[asn][s.LocalNode.RouterID] = NewLsNode(s.LocalNode.ASN, s.LocalNode.RouterID)
	}

	s.LocalNode = nodes[asn][s.LocalNode.RouterID]

	s.LocalNode.AddSrv6SID(s)
}

func (n *LsNode) AddSrv6SID(s *LsSrv6SID) {
	n.SRv6SIDs = append(n.SRv6SIDs, s)
}

type Metric struct {
	Type  MetricType `json:"type"`
	Value uint32     `json:"value"`
}

func NewMetric(metricType MetricType, value uint32) *Metric {
	return &Metric{
		Type:  metricType,
		Value: value,
	}
}

type MetricType int

const (
	IGPMetric MetricType = iota
	TEMetric
	DelayMetric
	HopcountMetric
)

func (m MetricType) String() string {
	switch m {
	case IGPMetric:
		return "METRIC_TYPE_IGP"
	case TEMetric:
		return "METRIC_TYPE_TE"
	case DelayMetric:
		return "METRIC_TYPE_DELAY"
	case HopcountMetric:
		return "METRIC_TYPE_HOPCOUNT"
	default:
		return "METRIC_TYPE_UNSPECIFIED"
	}
}

type Srv6EndXSID struct {
	EndpointBehavior uint16       `json:"endpoint_behavior"`
	Sids             []string     `json:"sids"`
	Srv6SIDStructure SIDStructure `json:"srv6_sid_structure"`
}
