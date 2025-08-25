// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"fmt"
	"net/netip"

	"go.uber.org/zap"
)

// AbstractedTED provides a lightweight abstracted view for H-PCE Parent PCE
// This implementation focuses on the minimal information required for interdomain path computation:
// 1. Domain identifiers
// 2. Border node information
// 3. Aggregated intra-domain path attributes
// 4. Inter-domain link attributes
type AbstractedTED struct {
	// Core abstracted topology as a graph
	borderNodes      map[uint32]map[string]*BorderNode // DomainID -> NodeID -> BorderNode
	intraDomainLinks map[uint32][]*IntraDomainPath     // DomainID -> Aggregated internal paths
	interDomainLinks []*InterDomainPath                // Direct inter-domain connections

	// Minimal domain metadata
	domainStatus map[uint32]DomainStatus // DomainID -> Status

	// Temporary for development/testing - will be removed in final version
	logger *zap.Logger
}

// BorderNode represents a simplified border node with minimal required information
type BorderNode struct {
	NodeID           string     // Border node identifier (Router ID)
	DomainID         uint32     // Domain this border node belongs to
	Address          netip.Addr // Border node address
	ConnectedDomains []uint32   // List of directly connected domains
}

// IntraDomainPath represents aggregated characteristics of paths within a domain
type IntraDomainPath struct {
	DomainID    uint32      // Domain containing this path
	EntryNodeID string      // Entry border node
	ExitNodeID  string      // Exit border node
	Metrics     PathMetrics // Aggregated path characteristics
}

// InterDomainPath represents direct physical links between domains
type InterDomainPath struct {
	LocalDomainID  uint32      // Source domain
	LocalNodeID    string      // Source border node
	RemoteDomainID uint32      // Destination domain
	RemoteNodeID   string      // Destination border node
	Metrics        PathMetrics // Link characteristics
}

// PathMetrics contains essential path/link characteristics for route computation
type PathMetrics struct {
	IGPMetric   uint32 // IGP metric
	TEMetric    uint32 // Traffic Engineering metric
	Delay       uint32 // Latency in microseconds
	Bandwidth   uint64 // Available bandwidth in bps
	AdminWeight uint32 // Administrative weight
}

// DomainStatus represents the operational status of a domain
type DomainStatus int

const (
	DomainStatusActive DomainStatus = iota
	DomainStatusInactive
)

// NewAbstractedTED creates a new lightweight abstracted TED
func NewAbstractedTED(logger *zap.Logger) *AbstractedTED {
	return &AbstractedTED{
		borderNodes:      make(map[uint32]map[string]*BorderNode),
		intraDomainLinks: make(map[uint32][]*IntraDomainPath),
		interDomainLinks: make([]*InterDomainPath, 0),
		domainStatus:     make(map[uint32]DomainStatus),
		logger:           logger.With(zap.String("component", "simplified-abstracted-ted")),
	}
}

// RegisterDomain registers a new domain with minimal metadata
func (ated *AbstractedTED) RegisterDomain(domainID uint32) error {
	if ated.borderNodes[domainID] == nil {
		ated.borderNodes[domainID] = make(map[string]*BorderNode)
	}
	if ated.intraDomainLinks[domainID] == nil {
		ated.intraDomainLinks[domainID] = make([]*IntraDomainPath, 0)
	}

	ated.domainStatus[domainID] = DomainStatusActive

	ated.logger.Info("Domain registered",
		zap.Uint32("domain-id", domainID))

	return nil
}

// AddBorderNode adds a border node to the abstracted topology
func (ated *AbstractedTED) AddBorderNode(node *BorderNode) error {
	if node == nil {
		return fmt.Errorf("border node cannot be nil")
	}

	// Ensure domain is registered
	if ated.borderNodes[node.DomainID] == nil {
		if err := ated.RegisterDomain(node.DomainID); err != nil {
			return err
		}
	}

	ated.borderNodes[node.DomainID][node.NodeID] = node

	ated.logger.Debug("Border node added",
		zap.Uint32("domain-id", node.DomainID),
		zap.String("node-id", node.NodeID),
		zap.String("address", node.Address.String()),
		zap.Any("connected-domains", node.ConnectedDomains))

	return nil
}

// AddIntraDomainPath adds an aggregated intra-domain path
func (ated *AbstractedTED) AddIntraDomainPath(path *IntraDomainPath) error {
	if path == nil {
		return fmt.Errorf("intra-domain path cannot be nil")
	}

	// Ensure domain is registered
	if ated.intraDomainLinks[path.DomainID] == nil {
		if err := ated.RegisterDomain(path.DomainID); err != nil {
			return err
		}
	}

	// Check if entry and exit nodes exist
	domain := ated.borderNodes[path.DomainID]
	if domain == nil {
		return fmt.Errorf("domain %d not found", path.DomainID)
	}
	if domain[path.EntryNodeID] == nil {
		return fmt.Errorf("entry node %s not found in domain %d", path.EntryNodeID, path.DomainID)
	}
	if domain[path.ExitNodeID] == nil {
		return fmt.Errorf("exit node %s not found in domain %d", path.ExitNodeID, path.DomainID)
	}

	ated.intraDomainLinks[path.DomainID] = append(ated.intraDomainLinks[path.DomainID], path)

	ated.logger.Debug("Intra-domain path added",
		zap.Uint32("domain-id", path.DomainID),
		zap.String("entry-node", path.EntryNodeID),
		zap.String("exit-node", path.ExitNodeID),
		zap.Uint32("igp-metric", path.Metrics.IGPMetric),
		zap.Uint32("te-metric", path.Metrics.TEMetric))

	return nil
}

// AddInterDomainPath adds a direct inter-domain connection
func (ated *AbstractedTED) AddInterDomainPath(path *InterDomainPath) error {
	if path == nil {
		return fmt.Errorf("inter-domain path cannot be nil")
	}

	// Validate that both border nodes exist
	localDomain := ated.borderNodes[path.LocalDomainID]
	if localDomain == nil || localDomain[path.LocalNodeID] == nil {
		return fmt.Errorf("local border node %s not found in domain %d",
			path.LocalNodeID, path.LocalDomainID)
	}

	remoteDomain := ated.borderNodes[path.RemoteDomainID]
	if remoteDomain == nil || remoteDomain[path.RemoteNodeID] == nil {
		return fmt.Errorf("remote border node %s not found in domain %d",
			path.RemoteNodeID, path.RemoteDomainID)
	}

	ated.interDomainLinks = append(ated.interDomainLinks, path)

	ated.logger.Debug("Inter-domain path added",
		zap.Uint32("local-domain", path.LocalDomainID),
		zap.String("local-node", path.LocalNodeID),
		zap.Uint32("remote-domain", path.RemoteDomainID),
		zap.String("remote-node", path.RemoteNodeID),
		zap.Uint32("igp-metric", path.Metrics.IGPMetric))

	return nil
}

// GetBorderNodes returns all border nodes for a domain
func (ated *AbstractedTED) GetBorderNodes(domainID uint32) map[string]*BorderNode {
	return ated.borderNodes[domainID]
}

// GetAllBorderNodes returns all border nodes across all domains
func (ated *AbstractedTED) GetAllBorderNodes() map[uint32]map[string]*BorderNode {
	return ated.borderNodes
}

// GetIntraDomainPaths returns aggregated intra-domain paths for a domain
func (ated *AbstractedTED) GetIntraDomainPaths(domainID uint32) []*IntraDomainPath {
	return ated.intraDomainLinks[domainID]
}

// GetInterDomainPaths returns all inter-domain connections
func (ated *AbstractedTED) GetInterDomainPaths() []*InterDomainPath {
	return ated.interDomainLinks
}

// GetConnectedDomains returns domains directly connected to the specified domain
func (ated *AbstractedTED) GetConnectedDomains(domainID uint32) []uint32 {
	connected := make(map[uint32]bool)

	// Check border nodes' connected domains
	if borderNodes := ated.borderNodes[domainID]; borderNodes != nil {
		for _, node := range borderNodes {
			for _, connectedDomain := range node.ConnectedDomains {
				if connectedDomain != domainID {
					connected[connectedDomain] = true
				}
			}
		}
	}

	// Check inter-domain links
	for _, link := range ated.interDomainLinks {
		if link.LocalDomainID == domainID {
			connected[link.RemoteDomainID] = true
		} else if link.RemoteDomainID == domainID {
			connected[link.LocalDomainID] = true
		}
	}

	result := make([]uint32, 0, len(connected))
	for domainID := range connected {
		result = append(result, domainID)
	}

	return result
}

// FindInterDomainPath computes a sequence of domains for interdomain path using simplified BFS
func (ated *AbstractedTED) FindInterDomainPath(srcDomainID, dstDomainID uint32) ([]uint32, error) {
	if srcDomainID == dstDomainID {
		return []uint32{srcDomainID}, nil
	}

	// Simple BFS on domain graph
	queue := [][]uint32{{srcDomainID}}
	visited := make(map[uint32]bool)
	visited[srcDomainID] = true

	for len(queue) > 0 {
		currentPath := queue[0]
		queue = queue[1:]
		currentDomain := currentPath[len(currentPath)-1]

		for _, neighborDomain := range ated.GetConnectedDomains(currentDomain) {
			// Only consider active domains for path computation
			if ated.GetDomainStatus(neighborDomain) != DomainStatusActive {
				continue
			}

			if neighborDomain == dstDomainID {
				result := append(currentPath, neighborDomain)
				ated.logger.Debug("Inter-domain path found",
					zap.Uint32("src-domain", srcDomainID),
					zap.Uint32("dst-domain", dstDomainID),
					zap.Any("path", result))
				return result, nil
			}

			if !visited[neighborDomain] {
				visited[neighborDomain] = true
				newPath := make([]uint32, len(currentPath))
				copy(newPath, currentPath)
				newPath = append(newPath, neighborDomain)
				queue = append(queue, newPath)
			}
		}
	}

	return nil, fmt.Errorf("no path found between domains %d and %d", srcDomainID, dstDomainID)
}

// GetDomainStatus returns the status of a domain
func (ated *AbstractedTED) GetDomainStatus(domainID uint32) DomainStatus {
	if status, exists := ated.domainStatus[domainID]; exists {
		return status
	}
	// If domain not registered, consider it inactive
	return DomainStatusInactive
}

// UpdateDomainStatus updates the status of a domain
func (ated *AbstractedTED) UpdateDomainStatus(domainID uint32, status DomainStatus) {
	ated.domainStatus[domainID] = status

	ated.logger.Info("Domain status updated",
		zap.Uint32("domain-id", domainID),
		zap.Int("status", int(status)))
}

// GetRegisteredDomains returns all registered domain IDs
func (ated *AbstractedTED) GetRegisteredDomains() []uint32 {
	domains := make([]uint32, 0, len(ated.domainStatus))
	for domainID := range ated.domainStatus {
		domains = append(domains, domainID)
	}
	return domains
}

// UnregisterDomain removes a domain from the abstracted TED
func (ated *AbstractedTED) UnregisterDomain(domainID uint32) {
	delete(ated.borderNodes, domainID)
	delete(ated.intraDomainLinks, domainID)
	delete(ated.domainStatus, domainID)

	// Remove inter-domain links involving this domain
	filteredLinks := make([]*InterDomainPath, 0)
	for _, link := range ated.interDomainLinks {
		if link.LocalDomainID != domainID && link.RemoteDomainID != domainID {
			filteredLinks = append(filteredLinks, link)
		}
	}
	ated.interDomainLinks = filteredLinks

	ated.logger.Info("Domain unregistered",
		zap.Uint32("domain-id", domainID))
}

// Print outputs the current state for debugging
func (ated *AbstractedTED) Print() {
	fmt.Println("=== Abstracted TED ===")

	fmt.Printf("Registered Domains: %v\n", ated.GetRegisteredDomains())

	fmt.Println("Border Nodes:")
	for domainID, nodes := range ated.borderNodes {
		fmt.Printf("  Domain %d: %d nodes\n", domainID, len(nodes))
		for nodeID, node := range nodes {
			fmt.Printf("    %s (%s) -> domains %v\n",
				nodeID, node.Address.String(), node.ConnectedDomains)
		}
	}

	fmt.Println("Intra-Domain Paths:")
	for domainID, paths := range ated.intraDomainLinks {
		fmt.Printf("  Domain %d: %d paths\n", domainID, len(paths))
		for _, path := range paths {
			fmt.Printf("    %s -> %s (IGP: %d, TE: %d)\n",
				path.EntryNodeID, path.ExitNodeID,
				path.Metrics.IGPMetric, path.Metrics.TEMetric)
		}
	}

	fmt.Printf("Inter-Domain Links: %d\n", len(ated.interDomainLinks))
	for _, link := range ated.interDomainLinks {
		fmt.Printf("  D%d:%s -> D%d:%s (IGP: %d)\n",
			link.LocalDomainID, link.LocalNodeID,
			link.RemoteDomainID, link.RemoteNodeID,
			link.Metrics.IGPMetric)
	}
}
