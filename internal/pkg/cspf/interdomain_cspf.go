// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/nttcom/pola/internal/pkg/table"
	"go.uber.org/zap"
)

// ObjectiveFunction defines different optimization objectives for interdomain path computation
type ObjectiveFunction int

const (
	// MinimizeTransitDomains minimizes the number of transit domains (RFC 8685)
	MinimizeTransitDomains ObjectiveFunction = iota
	// MinimizeBorderNodes minimizes the number of border nodes (RFC 8685)
	MinimizeBorderNodes
	// MinimizeCommonTransitDomains minimizes common transit domains for diverse paths (RFC 8685)
	MinimizeCommonTransitDomains
	// MinimizeCost minimizes the total path cost
	MinimizeCost
	// MinimizeLatency minimizes the total path latency
	MinimizeLatency
)

// PathConstraints defines constraints for interdomain path computation
type PathConstraints struct {
	MaxDomains      uint32         // Maximum number of domains in path
	ExcludedDomains []uint32       // Domains to exclude from path
	RequiredDomains []uint32       // Domains that must be included in path
	MaxCost         uint32         // Maximum acceptable path cost
	MaxLatency      uint32         // Maximum acceptable path latency (microseconds)
	MinBandwidth    uint64         // Minimum required bandwidth
	DiversityPath   []uint32       // Path to be diverse from (for backup paths)
	DiversityLevel  DiversityLevel // Level of diversity required
}

// DiversityLevel defines the level of path diversity
type DiversityLevel int

const (
	NoDiversity DiversityLevel = iota
	LinkDiverse
	NodeDiverse
	DomainDiverse
)

// InterdomainPathRequest represents a request for interdomain path computation
type InterdomainPathRequest struct {
	RequestID   uint32
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcDomainID uint32
	DstDomainID uint32
	Objective   ObjectiveFunction
	MetricType  table.MetricType
	Constraints *PathConstraints
}

// InterdomainPathResponse represents the response from interdomain path computation
type InterdomainPathResponse struct {
	RequestID      uint32
	Success        bool
	ErrorMessage   string
	DomainSequence []uint32
	TotalCost      uint32
	TotalLatency   uint32
	BorderNodes    map[uint32][]netip.Addr // Domain -> Border node addresses
	Metrics        *InterdomainPathMetrics
}

// InterdomainPathMetrics contains computed path metrics
type InterdomainPathMetrics struct {
	DomainCount        int
	BorderNodeCount    int
	TotalCost          uint32
	TotalLatency       uint32
	EstimatedBandwidth uint64
	DiversityScore     float64 // How diverse this path is from existing paths
}

// domainNode represents a domain in the interdomain graph
type domainNode struct {
	domainID    uint32
	calculated  bool
	cost        uint32
	latency     uint32
	prevDomain  uint32
	borderNodes []netip.Addr
}

// InterdomainCSPF implements constrained shortest path first for interdomain routing
type InterdomainCSPF struct {
	interdomainTED *table.AbstractedTED
	logger         *zap.Logger
}

// NewInterdomainCSPF creates a new interdomain CSPF instance
func NewInterdomainCSPF(interdomainTED *table.AbstractedTED, logger *zap.Logger) *InterdomainCSPF {
	return &InterdomainCSPF{
		interdomainTED: interdomainTED,
		logger:         logger.With(zap.String("component", "interdomain-cspf")),
	}
}

// ComputePath computes an interdomain path based on the given request
func (cspf *InterdomainCSPF) ComputePath(request *InterdomainPathRequest) (*InterdomainPathResponse, error) {
	if request == nil {
		return nil, errors.New("path request cannot be nil")
	}

	cspf.logger.Info("Computing interdomain path",
		zap.Uint32("request-id", request.RequestID),
		zap.Uint32("src-domain", request.SrcDomainID),
		zap.Uint32("dst-domain", request.DstDomainID),
		zap.Int("objective", int(request.Objective)))

	// Validate request
	if err := cspf.validateRequest(request); err != nil {
		return &InterdomainPathResponse{
			RequestID:    request.RequestID,
			Success:      false,
			ErrorMessage: fmt.Sprintf("invalid request: %v", err),
		}, nil
	}

	// Compute domain-level path
	domainPath, metrics, err := cspf.computeDomainPath(request)
	if err != nil {
		return &InterdomainPathResponse{
			RequestID:    request.RequestID,
			Success:      false,
			ErrorMessage: fmt.Sprintf("path computation failed: %v", err),
		}, nil
	}

	// Find border nodes for interdomain connections
	borderNodes, err := cspf.findBorderNodes(domainPath)
	if err != nil {
		cspf.logger.Warn("Failed to find border nodes", zap.Error(err))
		// Continue without border node information
		borderNodes = make(map[uint32][]netip.Addr)
	}

	cspf.logger.Info("Interdomain path computed successfully",
		zap.Uint32("request-id", request.RequestID),
		zap.Any("domain-path", domainPath),
		zap.Uint32("total-cost", metrics.TotalCost),
		zap.Int("domain-count", metrics.DomainCount))

	return &InterdomainPathResponse{
		RequestID:      request.RequestID,
		Success:        true,
		DomainSequence: domainPath,
		TotalCost:      metrics.TotalCost,
		TotalLatency:   metrics.TotalLatency,
		BorderNodes:    borderNodes,
		Metrics:        metrics,
	}, nil
}

// validateRequest validates the interdomain path request
func (cspf *InterdomainCSPF) validateRequest(request *InterdomainPathRequest) error {
	if request.SrcDomainID == 0 || request.DstDomainID == 0 {
		return errors.New("source and destination domain IDs must be non-zero")
	}

	if !request.SrcAddr.IsValid() || !request.DstAddr.IsValid() {
		return errors.New("source and destination addresses must be valid")
	}

	// Check if domains exist in the interdomain TED
	if cspf.interdomainTED.GetDomainMetadata(request.SrcDomainID) == nil {
		return fmt.Errorf("source domain %d not found", request.SrcDomainID)
	}

	if cspf.interdomainTED.GetDomainMetadata(request.DstDomainID) == nil {
		return fmt.Errorf("destination domain %d not found", request.DstDomainID)
	}

	return nil
}

// computeDomainPath computes the sequence of domains using the specified objective
func (cspf *InterdomainCSPF) computeDomainPath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	switch request.Objective {
	case MinimizeTransitDomains:
		return cspf.computeShortestDomainPath(request)
	case MinimizeBorderNodes:
		return cspf.computeMinBorderNodePath(request)
	case MinimizeCost:
		return cspf.computeMinCostPath(request)
	case MinimizeLatency:
		return cspf.computeMinLatencyPath(request)
	case MinimizeCommonTransitDomains:
		return cspf.computeDiversePath(request)
	default:
		return cspf.computeShortestDomainPath(request)
	}
}

// computeShortestDomainPath computes the path with minimum number of transit domains
func (cspf *InterdomainCSPF) computeShortestDomainPath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	if request.SrcDomainID == request.DstDomainID {
		return []uint32{request.SrcDomainID}, &InterdomainPathMetrics{
			DomainCount: 1,
			TotalCost:   0,
		}, nil
	}

	// Use breadth-first search for shortest path in terms of domain count
	queue := [][]uint32{{request.SrcDomainID}}
	visited := make(map[uint32]bool)
	visited[request.SrcDomainID] = true

	connections := cspf.interdomainTED.GetDomainConnections()

	for len(queue) > 0 {
		currentPath := queue[0]
		queue = queue[1:]
		currentDomain := currentPath[len(currentPath)-1]

		// Check constraints
		if request.Constraints != nil {
			if request.Constraints.MaxDomains > 0 && len(currentPath) >= int(request.Constraints.MaxDomains) {
				continue
			}

			if cspf.isDomainExcluded(currentDomain, request.Constraints.ExcludedDomains) {
				continue
			}
		}

		for _, neighborDomain := range connections[currentDomain] {
			if neighborDomain == request.DstDomainID {
				// Found destination
				finalPath := append(currentPath, neighborDomain)
				metrics := &InterdomainPathMetrics{
					DomainCount: len(finalPath),
					TotalCost:   uint32(len(finalPath) - 1), // Each hop costs 1
				}
				return finalPath, metrics, nil
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

	return nil, nil, fmt.Errorf("no path found between domains %d and %d", request.SrcDomainID, request.DstDomainID)
}

// computeMinCostPath computes the path with minimum total cost
func (cspf *InterdomainCSPF) computeMinCostPath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	return cspf.dijkstraBasedSearch(request, func(from, to uint32) uint32 {
		// For now, use a simple cost model
		// In practice, this could be based on actual link metrics from border nodes
		return 10 // Base interdomain link cost
	})
}

// computeMinLatencyPath computes the path with minimum total latency
func (cspf *InterdomainCSPF) computeMinLatencyPath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	return cspf.dijkstraBasedSearch(request, func(from, to uint32) uint32 {
		// Simplified latency model - could be enhanced with real measurements
		return 5000 // 5ms base latency between domains
	})
}

// computeMinBorderNodePath computes the path that minimizes border node usage
func (cspf *InterdomainCSPF) computeMinBorderNodePath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	return cspf.dijkstraBasedSearch(request, func(from, to uint32) uint32 {
		// Cost is based on number of border nodes between domains
		borderNodes1, borderNodes2, err := cspf.interdomainTED.GetBorderNodesBetweenDomains(from, to)
		if err != nil {
			return math.MaxUint32 / 2 // Very high cost if no connection
		}
		return uint32(len(borderNodes1) + len(borderNodes2))
	})
}

// computeDiversePath computes a path that is diverse from existing paths
func (cspf *InterdomainCSPF) computeDiversePath(request *InterdomainPathRequest) ([]uint32, *InterdomainPathMetrics, error) {
	if request.Constraints == nil || len(request.Constraints.DiversityPath) == 0 {
		// If no diversity path specified, fall back to shortest path
		return cspf.computeShortestDomainPath(request)
	}

	// Modify edge costs to avoid domains in the diversity path
	diversityPenalty := uint32(1000) // High penalty for reusing domains

	return cspf.dijkstraBasedSearch(request, func(from, to uint32) uint32 {
		baseCost := uint32(10) // Base interdomain cost

		// Add penalty if either domain is in the diversity path
		for _, diverseDomain := range request.Constraints.DiversityPath {
			if from == diverseDomain || to == diverseDomain {
				baseCost += diversityPenalty
				break
			}
		}

		return baseCost
	})
}

// dijkstraBasedSearch performs Dijkstra's algorithm with custom cost function
func (cspf *InterdomainCSPF) dijkstraBasedSearch(
	request *InterdomainPathRequest,
	costFunc func(from, to uint32) uint32,
) ([]uint32, *InterdomainPathMetrics, error) {

	if request.SrcDomainID == request.DstDomainID {
		return []uint32{request.SrcDomainID}, &InterdomainPathMetrics{
			DomainCount: 1,
			TotalCost:   0,
		}, nil
	}

	domains := make(map[uint32]*domainNode)
	connections := cspf.interdomainTED.GetDomainConnections()

	// Initialize all domains
	for domainID := range connections {
		domains[domainID] = &domainNode{
			domainID:   domainID,
			calculated: false,
			cost:       math.MaxUint32,
			prevDomain: 0,
		}
	}

	// Set source domain cost to 0
	domains[request.SrcDomainID].cost = 0

	for {
		// Find next domain to process
		nextDomainID, err := cspf.getNextDomainNode(domains)
		if err != nil {
			break
		}

		if nextDomainID == request.DstDomainID {
			break
		}

		currentDomain := domains[nextDomainID]
		currentDomain.calculated = true

		// Process all neighbors
		for _, neighborID := range connections[nextDomainID] {
			if domains[neighborID].calculated {
				continue
			}

			// Check constraints
			if request.Constraints != nil {
				if cspf.isDomainExcluded(neighborID, request.Constraints.ExcludedDomains) {
					continue
				}
			}

			linkCost := costFunc(nextDomainID, neighborID)
			newCost := currentDomain.cost + linkCost

			if newCost < domains[neighborID].cost {
				domains[neighborID].cost = newCost
				domains[neighborID].prevDomain = nextDomainID
			}
		}
	}

	// Check if destination is reachable
	if domains[request.DstDomainID].cost == math.MaxUint32 {
		return nil, nil, fmt.Errorf("no path found between domains %d and %d", request.SrcDomainID, request.DstDomainID)
	}

	// Reconstruct path
	var path []uint32
	for domainID := request.DstDomainID; domainID != 0; domainID = domains[domainID].prevDomain {
		path = append(path, domainID)
		if domainID == request.SrcDomainID {
			break
		}
	}

	// Reverse path
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	metrics := &InterdomainPathMetrics{
		DomainCount: len(path),
		TotalCost:   domains[request.DstDomainID].cost,
	}

	return path, metrics, nil
}

// getNextDomainNode returns the next domain to process in Dijkstra's algorithm
func (cspf *InterdomainCSPF) getNextDomainNode(domains map[uint32]*domainNode) (uint32, error) {
	var nextDomainID uint32
	minCost := uint32(math.MaxUint32)
	found := false

	for domainID, domain := range domains {
		if !domain.calculated && domain.cost < minCost {
			minCost = domain.cost
			nextDomainID = domainID
			found = true
		}
	}

	if !found {
		return 0, errors.New("no more domains to process")
	}

	return nextDomainID, nil
}

// isDomainExcluded checks if a domain is in the excluded list
func (cspf *InterdomainCSPF) isDomainExcluded(domainID uint32, excludedDomains []uint32) bool {
	for _, excluded := range excludedDomains {
		if domainID == excluded {
			return true
		}
	}
	return false
}

// findBorderNodes finds border nodes for each domain in the path
func (cspf *InterdomainCSPF) findBorderNodes(domainPath []uint32) (map[uint32][]netip.Addr, error) {
	borderNodes := make(map[uint32][]netip.Addr)

	for i := 0; i < len(domainPath); i++ {
		domainID := domainPath[i]
		domainBorderNodes := cspf.interdomainTED.GetBorderNodes(domainID)

		var addresses []netip.Addr
		for _, borderNode := range domainBorderNodes {
			addresses = append(addresses, borderNode.Address)
		}

		borderNodes[domainID] = addresses
	}

	return borderNodes, nil
}

// ComputeMultiplePaths computes multiple diverse paths between domains
func (cspf *InterdomainCSPF) ComputeMultiplePaths(
	request *InterdomainPathRequest,
	pathCount int,
) ([]*InterdomainPathResponse, error) {

	if pathCount <= 0 {
		return nil, errors.New("path count must be positive")
	}

	var responses []*InterdomainPathResponse
	usedDomains := make(map[uint32]bool)

	for i := 0; i < pathCount; i++ {
		// Modify request for diversity
		diverseRequest := *request
		if request.Constraints == nil {
			diverseRequest.Constraints = &PathConstraints{}
		}

		// Add previously used domains to exclusion list for diversity
		if i > 0 {
			for domainID := range usedDomains {
				diverseRequest.Constraints.ExcludedDomains = append(
					diverseRequest.Constraints.ExcludedDomains, domainID)
			}
		}

		response, err := cspf.ComputePath(&diverseRequest)
		if err != nil || !response.Success {
			break // No more diverse paths available
		}

		responses = append(responses, response)

		// Track domains used in this path
		for _, domainID := range response.DomainSequence {
			usedDomains[domainID] = true
		}
	}

	if len(responses) == 0 {
		return nil, errors.New("no paths found")
	}

	cspf.logger.Info("Multiple interdomain paths computed",
		zap.Int("requested-paths", pathCount),
		zap.Int("computed-paths", len(responses)))

	return responses, nil
}

// ValidatePath validates if a given domain sequence is feasible
func (cspf *InterdomainCSPF) ValidatePath(domainSequence []uint32) error {
	if len(domainSequence) == 0 {
		return errors.New("empty domain sequence")
	}

	if len(domainSequence) == 1 {
		return nil // Single domain path is always valid
	}

	connections := cspf.interdomainTED.GetDomainConnections()

	// Check connectivity between consecutive domains
	for i := 0; i < len(domainSequence)-1; i++ {
		currentDomain := domainSequence[i]
		nextDomain := domainSequence[i+1]

		// Check if domains are connected
		connected := false
		for _, connectedDomain := range connections[currentDomain] {
			if connectedDomain == nextDomain {
				connected = true
				break
			}
		}

		if !connected {
			return fmt.Errorf("domains %d and %d are not connected", currentDomain, nextDomain)
		}
	}

	return nil
}

// GetPathMetrics computes detailed metrics for a given domain path
func (cspf *InterdomainCSPF) GetPathMetrics(domainSequence []uint32) (*InterdomainPathMetrics, error) {
	if err := cspf.ValidatePath(domainSequence); err != nil {
		return nil, err
	}

	metrics := &InterdomainPathMetrics{
		DomainCount: len(domainSequence),
	}

	// Calculate border node count and other metrics
	for i := 0; i < len(domainSequence)-1; i++ {
		currentDomain := domainSequence[i]
		nextDomain := domainSequence[i+1]

		borderNodes1, borderNodes2, err := cspf.interdomainTED.GetBorderNodesBetweenDomains(currentDomain, nextDomain)
		if err == nil {
			metrics.BorderNodeCount += len(borderNodes1) + len(borderNodes2)
		}

		// Add estimated interdomain link cost and latency
		metrics.TotalCost += 10      // Base cost per interdomain hop
		metrics.TotalLatency += 5000 // 5ms base latency per hop
	}

	return metrics, nil
}
