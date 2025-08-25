// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"fmt"
	"net/netip"
	"time"

	"go.uber.org/zap"
)

// InterdomainSRPolicy manages SR policies that span multiple domains for H-PCE
type InterdomainSRPolicy struct {
	PlspID           uint32                     // PCEP LSP identifier
	Name             string                     // SR policy name
	SrcAddr          netip.Addr                 // Source address
	DstAddr          netip.Addr                 // Destination address
	Color            uint32                     // SR policy color
	Preference       uint32                     // SR policy preference
	State            PolicyState                // Overall policy state
	DomainSequence   []uint32                   // Ordered list of domains in the path
	PerDomainPolicies map[uint32]*DomainSRPolicy // Domain-specific policy segments
	CreatedAt        time.Time                  // Policy creation time
	LastUpdated      time.Time                  // Last update time
	RequestID        uint32                     // Original path computation request ID
}

// DomainSRPolicy represents an SR policy segment within a single domain
type DomainSRPolicy struct {
	DomainID       uint32        // Domain identifier
	LocalPlspID    uint32        // Domain-local PLSP ID
	SegmentList    []Segment     // Segment list for this domain
	EntryPoint     netip.Addr    // Domain entry point address
	ExitPoint      netip.Addr    // Domain exit point address
	State          PolicyState   // Domain-specific policy state
	ChildPCEAddr   netip.Addr    // Child PCE managing this domain
	LastUpdated    time.Time     // Last update from Child PCE
	Metrics        *PolicyMetrics // Policy metrics for this domain
}

// PolicyMetrics contains performance metrics for an SR policy segment
type PolicyMetrics struct {
	Bandwidth       uint64        // Allocated bandwidth
	Latency         uint32        // Path latency in microseconds
	UtilizedBandwidth uint64      // Currently utilized bandwidth
	PacketLoss      float32       // Packet loss percentage
	Availability    float32       // Path availability percentage
	LastMeasured    time.Time     // Last measurement time
}

// InterdomainSRPolicyManager manages all interdomain SR policies
type InterdomainSRPolicyManager struct {
	policies    map[uint32]*InterdomainSRPolicy // PlspID -> Policy
	policyIndex map[string][]*InterdomainSRPolicy // Index by various keys
	logger      *zap.Logger
}

// NewInterdomainSRPolicyManager creates a new interdomain SR policy manager
func NewInterdomainSRPolicyManager(logger *zap.Logger) *InterdomainSRPolicyManager {
	return &InterdomainSRPolicyManager{
		policies:    make(map[uint32]*InterdomainSRPolicy),
		policyIndex: make(map[string][]*InterdomainSRPolicy),
		logger:      logger.With(zap.String("component", "interdomain-sr-policy")),
	}
}

// CreateInterdomainSRPolicy creates a new interdomain SR policy
func (mgr *InterdomainSRPolicyManager) CreateInterdomainSRPolicy(
	plspID uint32,
	name string,
	srcAddr, dstAddr netip.Addr,
	color, preference uint32,
	domainSequence []uint32,
	requestID uint32,
) (*InterdomainSRPolicy, error) {

	if _, exists := mgr.policies[plspID]; exists {
		return nil, fmt.Errorf("policy with PLSP ID %d already exists", plspID)
	}

	if len(domainSequence) == 0 {
		return nil, fmt.Errorf("domain sequence cannot be empty")
	}

	policy := &InterdomainSRPolicy{
		PlspID:            plspID,
		Name:              name,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
		Color:             color,
		Preference:        preference,
		State:             PolicyDown,
		DomainSequence:    domainSequence,
		PerDomainPolicies: make(map[uint32]*DomainSRPolicy),
		CreatedAt:         time.Now(),
		LastUpdated:       time.Now(),
		RequestID:         requestID,
	}

	// Initialize per-domain policies
	for _, domainID := range domainSequence {
		policy.PerDomainPolicies[domainID] = &DomainSRPolicy{
			DomainID:    domainID,
			State:       PolicyDown,
			LastUpdated: time.Now(),
			Metrics:     &PolicyMetrics{LastMeasured: time.Now()},
		}
	}

	mgr.policies[plspID] = policy
	mgr.updateIndex(policy)

	mgr.logger.Info("Interdomain SR policy created",
		zap.Uint32("plsp-id", plspID),
		zap.String("name", name),
		zap.String("src", srcAddr.String()),
		zap.String("dst", dstAddr.String()),
		zap.Uint32("color", color),
		zap.Any("domain-sequence", domainSequence))

	return policy, nil
}

// UpdateDomainPolicy updates the policy segment for a specific domain
func (mgr *InterdomainSRPolicyManager) UpdateDomainPolicy(
	plspID, domainID uint32,
	segmentList []Segment,
	entryPoint, exitPoint netip.Addr,
	childPCEAddr netip.Addr,
) error {

	policy := mgr.policies[plspID]
	if policy == nil {
		return fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	domainPolicy := policy.PerDomainPolicies[domainID]
	if domainPolicy == nil {
		return fmt.Errorf("domain %d not found in policy %d", domainID, plspID)
	}

	domainPolicy.SegmentList = segmentList
	domainPolicy.EntryPoint = entryPoint
	domainPolicy.ExitPoint = exitPoint
	domainPolicy.ChildPCEAddr = childPCEAddr
	domainPolicy.State = PolicyUp
	domainPolicy.LastUpdated = time.Now()

	policy.LastUpdated = time.Now()

	// Check if all domains are up to update overall policy state
	mgr.updateOverallPolicyState(policy)

	mgr.logger.Info("Domain policy updated",
		zap.Uint32("plsp-id", plspID),
		zap.Uint32("domain-id", domainID),
		zap.Int("segment-count", len(segmentList)),
		zap.String("entry-point", entryPoint.String()),
		zap.String("exit-point", exitPoint.String()))

	return nil
}

// updateOverallPolicyState updates the overall policy state based on domain states
func (mgr *InterdomainSRPolicyManager) updateOverallPolicyState(policy *InterdomainSRPolicy) {
	allUp := true
	anyUp := false

	for _, domainPolicy := range policy.PerDomainPolicies {
		if domainPolicy.State != PolicyUp {
			allUp = false
		} else {
			anyUp = true
		}
	}

	var newState PolicyState
	if allUp {
		newState = PolicyActive
	} else if anyUp {
		newState = PolicyUp
	} else {
		newState = PolicyDown
	}

	if policy.State != newState {
		oldState := policy.State
		policy.State = newState
		mgr.logger.Info("Policy state changed",
			zap.Uint32("plsp-id", policy.PlspID),
			zap.String("old-state", string(oldState)),
			zap.String("new-state", string(newState)))
	}
}

// GetInterdomainSRPolicy retrieves an interdomain SR policy by PLSP ID
func (mgr *InterdomainSRPolicyManager) GetInterdomainSRPolicy(plspID uint32) *InterdomainSRPolicy {
	return mgr.policies[plspID]
}

// GetPoliciesByColor retrieves all policies with a specific color
func (mgr *InterdomainSRPolicyManager) GetPoliciesByColor(color uint32) []*InterdomainSRPolicy {
	colorKey := fmt.Sprintf("color:%d", color)
	return mgr.policyIndex[colorKey]
}

// GetPoliciesByDestination retrieves all policies with a specific destination
func (mgr *InterdomainSRPolicyManager) GetPoliciesByDestination(dstAddr netip.Addr) []*InterdomainSRPolicy {
	dstKey := fmt.Sprintf("dst:%s", dstAddr.String())
	return mgr.policyIndex[dstKey]
}

// GetPoliciesByDomain retrieves all policies that traverse a specific domain
func (mgr *InterdomainSRPolicyManager) GetPoliciesByDomain(domainID uint32) []*InterdomainSRPolicy {
	domainKey := fmt.Sprintf("domain:%d", domainID)
	return mgr.policyIndex[domainKey]
}

// GetAllPolicies returns all interdomain SR policies
func (mgr *InterdomainSRPolicyManager) GetAllPolicies() map[uint32]*InterdomainSRPolicy {
	return mgr.policies
}

// DeleteInterdomainSRPolicy removes an interdomain SR policy
func (mgr *InterdomainSRPolicyManager) DeleteInterdomainSRPolicy(plspID uint32) error {
	policy := mgr.policies[plspID]
	if policy == nil {
		return fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	delete(mgr.policies, plspID)
	mgr.removeFromIndex(policy)

	mgr.logger.Info("Interdomain SR policy deleted",
		zap.Uint32("plsp-id", plspID),
		zap.String("name", policy.Name))

	return nil
}

// UpdatePolicyMetrics updates performance metrics for a domain policy
func (mgr *InterdomainSRPolicyManager) UpdatePolicyMetrics(
	plspID, domainID uint32,
	metrics *PolicyMetrics,
) error {

	policy := mgr.policies[plspID]
	if policy == nil {
		return fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	domainPolicy := policy.PerDomainPolicies[domainID]
	if domainPolicy == nil {
		return fmt.Errorf("domain %d not found in policy %d", domainID, plspID)
	}

	domainPolicy.Metrics = metrics
	metrics.LastMeasured = time.Now()

	mgr.logger.Debug("Policy metrics updated",
		zap.Uint32("plsp-id", plspID),
		zap.Uint32("domain-id", domainID),
		zap.Uint64("bandwidth", metrics.Bandwidth),
		zap.Uint32("latency", metrics.Latency))

	return nil
}

// GetPolicyMetrics retrieves aggregated metrics for an interdomain policy
func (mgr *InterdomainSRPolicyManager) GetPolicyMetrics(plspID uint32) (*PolicyMetrics, error) {
	policy := mgr.policies[plspID]
	if policy == nil {
		return nil, fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	// Aggregate metrics across all domains
	var totalBandwidth, totalUtilizedBandwidth uint64
	var totalLatency uint32
	var minAvailability float32 = 100.0
	var maxPacketLoss float32
	var latestMeasurement time.Time

	domainCount := len(policy.PerDomainPolicies)
	if domainCount == 0 {
		return &PolicyMetrics{}, nil
	}

	for _, domainPolicy := range policy.PerDomainPolicies {
		metrics := domainPolicy.Metrics
		if metrics == nil {
			continue
		}

		totalBandwidth += metrics.Bandwidth
		totalUtilizedBandwidth += metrics.UtilizedBandwidth
		totalLatency += metrics.Latency

		if metrics.Availability < minAvailability {
			minAvailability = metrics.Availability
		}

		if metrics.PacketLoss > maxPacketLoss {
			maxPacketLoss = metrics.PacketLoss
		}

		if metrics.LastMeasured.After(latestMeasurement) {
			latestMeasurement = metrics.LastMeasured
		}
	}

	return &PolicyMetrics{
		Bandwidth:         totalBandwidth / uint64(domainCount), // Average bandwidth
		Latency:           totalLatency,                         // Sum of latencies
		UtilizedBandwidth: totalUtilizedBandwidth,
		PacketLoss:        maxPacketLoss,     // Worst-case packet loss
		Availability:      minAvailability,   // Worst-case availability
		LastMeasured:      latestMeasurement,
	}, nil
}

// updateIndex updates the policy index for efficient lookups
func (mgr *InterdomainSRPolicyManager) updateIndex(policy *InterdomainSRPolicy) {
	// Index by color
	colorKey := fmt.Sprintf("color:%d", policy.Color)
	mgr.policyIndex[colorKey] = append(mgr.policyIndex[colorKey], policy)

	// Index by destination
	dstKey := fmt.Sprintf("dst:%s", policy.DstAddr.String())
	mgr.policyIndex[dstKey] = append(mgr.policyIndex[dstKey], policy)

	// Index by domains
	for _, domainID := range policy.DomainSequence {
		domainKey := fmt.Sprintf("domain:%d", domainID)
		mgr.policyIndex[domainKey] = append(mgr.policyIndex[domainKey], policy)
	}
}

// removeFromIndex removes a policy from all indexes
func (mgr *InterdomainSRPolicyManager) removeFromIndex(policy *InterdomainSRPolicy) {
	// Remove from color index
	colorKey := fmt.Sprintf("color:%d", policy.Color)
	mgr.policyIndex[colorKey] = mgr.removePolicyFromSlice(mgr.policyIndex[colorKey], policy)

	// Remove from destination index
	dstKey := fmt.Sprintf("dst:%s", policy.DstAddr.String())
	mgr.policyIndex[dstKey] = mgr.removePolicyFromSlice(mgr.policyIndex[dstKey], policy)

	// Remove from domain indexes
	for _, domainID := range policy.DomainSequence {
		domainKey := fmt.Sprintf("domain:%d", domainID)
		mgr.policyIndex[domainKey] = mgr.removePolicyFromSlice(mgr.policyIndex[domainKey], policy)
	}
}

// removePolicyFromSlice removes a policy from a slice
func (mgr *InterdomainSRPolicyManager) removePolicyFromSlice(slice []*InterdomainSRPolicy, policy *InterdomainSRPolicy) []*InterdomainSRPolicy {
	for i, p := range slice {
		if p.PlspID == policy.PlspID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// GenerateEndToEndSegmentList creates a complete segment list by concatenating domain segments
func (mgr *InterdomainSRPolicyManager) GenerateEndToEndSegmentList(plspID uint32) ([]Segment, error) {
	policy := mgr.policies[plspID]
	if policy == nil {
		return nil, fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	var endToEndSegments []Segment

	// Concatenate segments from each domain in sequence
	for _, domainID := range policy.DomainSequence {
		domainPolicy := policy.PerDomainPolicies[domainID]
		if domainPolicy == nil || len(domainPolicy.SegmentList) == 0 {
			return nil, fmt.Errorf("domain %d has no segments in policy %d", domainID, plspID)
		}

		endToEndSegments = append(endToEndSegments, domainPolicy.SegmentList...)
	}

	mgr.logger.Debug("End-to-end segment list generated",
		zap.Uint32("plsp-id", plspID),
		zap.Int("total-segments", len(endToEndSegments)),
		zap.Int("domains", len(policy.DomainSequence)))

	return endToEndSegments, nil
}

// ValidatePolicy performs consistency checks on an interdomain SR policy
func (mgr *InterdomainSRPolicyManager) ValidatePolicy(plspID uint32) []string {
	policy := mgr.policies[plspID]
	if policy == nil {
		return []string{"policy not found"}
	}

	var issues []string

	// Check if all domains have policy segments
	for _, domainID := range policy.DomainSequence {
		domainPolicy := policy.PerDomainPolicies[domainID]
		if domainPolicy == nil {
			issues = append(issues, fmt.Sprintf("missing policy for domain %d", domainID))
			continue
		}

		if len(domainPolicy.SegmentList) == 0 {
			issues = append(issues, fmt.Sprintf("empty segment list for domain %d", domainID))
		}

		if !domainPolicy.EntryPoint.IsValid() && domainID != policy.DomainSequence[0] {
			issues = append(issues, fmt.Sprintf("missing entry point for domain %d", domainID))
		}

		if !domainPolicy.ExitPoint.IsValid() && domainID != policy.DomainSequence[len(policy.DomainSequence)-1] {
			issues = append(issues, fmt.Sprintf("missing exit point for domain %d", domainID))
		}
	}

	// Check connectivity between adjacent domains
	for i := 0; i < len(policy.DomainSequence)-1; i++ {
		currentDomain := policy.DomainSequence[i]
		nextDomain := policy.DomainSequence[i+1]

		currentPolicy := policy.PerDomainPolicies[currentDomain]
		nextPolicy := policy.PerDomainPolicies[nextDomain]

		if currentPolicy != nil && nextPolicy != nil {
			// Check if exit point of current domain matches entry point of next domain
			if currentPolicy.ExitPoint.IsValid() && nextPolicy.EntryPoint.IsValid() {
				// This is a simplified check - in practice, you might need more sophisticated validation
				if currentPolicy.ExitPoint != nextPolicy.EntryPoint {
					issues = append(issues, fmt.Sprintf("connectivity gap between domains %d and %d", currentDomain, nextDomain))
				}
			}
		}
	}

	return issues
}

// GetPolicyStatus returns a comprehensive status of an interdomain SR policy
func (mgr *InterdomainSRPolicyManager) GetPolicyStatus(plspID uint32) (*InterdomainSRPolicyStatus, error) {
	policy := mgr.policies[plspID]
	if policy == nil {
		return nil, fmt.Errorf("policy with PLSP ID %d not found", plspID)
	}

	status := &InterdomainSRPolicyStatus{
		PlspID:         policy.PlspID,
		Name:           policy.Name,
		OverallState:   policy.State,
		DomainCount:    len(policy.DomainSequence),
		CreatedAt:      policy.CreatedAt,
		LastUpdated:    policy.LastUpdated,
		DomainStatuses: make(map[uint32]*DomainPolicyStatus),
		ValidationIssues: mgr.ValidatePolicy(plspID),
	}

	// Collect domain-specific statuses
	for domainID, domainPolicy := range policy.PerDomainPolicies {
		status.DomainStatuses[domainID] = &DomainPolicyStatus{
			DomainID:     domainID,
			State:        domainPolicy.State,
			SegmentCount: len(domainPolicy.SegmentList),
			EntryPoint:   domainPolicy.EntryPoint,
			ExitPoint:    domainPolicy.ExitPoint,
			LastUpdated:  domainPolicy.LastUpdated,
		}
	}

	return status, nil
}

// InterdomainSRPolicyStatus provides comprehensive status information
type InterdomainSRPolicyStatus struct {
	PlspID           uint32                         `json:"plsp_id"`
	Name             string                         `json:"name"`
	OverallState     PolicyState                    `json:"overall_state"`
	DomainCount      int                            `json:"domain_count"`
	CreatedAt        time.Time                      `json:"created_at"`
	LastUpdated      time.Time                      `json:"last_updated"`
	DomainStatuses   map[uint32]*DomainPolicyStatus `json:"domain_statuses"`
	ValidationIssues []string                       `json:"validation_issues"`
}

// DomainPolicyStatus provides status information for a domain-specific policy segment
type DomainPolicyStatus struct {
	DomainID     uint32     `json:"domain_id"`
	State        PolicyState `json:"state"`
	SegmentCount int        `json:"segment_count"`
	EntryPoint   netip.Addr `json:"entry_point"`
	ExitPoint    netip.Addr `json:"exit_point"`
	LastUpdated  time.Time  `json:"last_updated"`
}

// Print outputs the current state of all interdomain SR policies for debugging
func (mgr *InterdomainSRPolicyManager) Print() {
	fmt.Println("=== Interdomain SR Policies ===")

	if len(mgr.policies) == 0 {
		fmt.Println("No interdomain SR policies configured")
		return
	}

	for plspID, policy := range mgr.policies {
		fmt.Printf("Policy %d (%s):\n", plspID, policy.Name)
		fmt.Printf("  State: %s\n", policy.State)
		fmt.Printf("  Source: %s -> Destination: %s\n", policy.SrcAddr.String(), policy.DstAddr.String())
		fmt.Printf("  Color: %d, Preference: %d\n", policy.Color, policy.Preference)
		fmt.Printf("  Domain Sequence: %v\n", policy.DomainSequence)
		fmt.Printf("  Created: %s, Last Updated: %s\n", policy.CreatedAt.Format(time.RFC3339), policy.LastUpdated.Format(time.RFC3339))

		fmt.Printf("  Per-Domain Policies:\n")
		for _, domainID := range policy.DomainSequence {
			domainPolicy := policy.PerDomainPolicies[domainID]
			if domainPolicy != nil {
				fmt.Printf("    Domain %d: %s, %d segments, Entry: %s, Exit: %s\n",
					domainID, domainPolicy.State, len(domainPolicy.SegmentList),
					domainPolicy.EntryPoint.String(), domainPolicy.ExitPoint.String())
			}
		}

		fmt.Println()
	}
}