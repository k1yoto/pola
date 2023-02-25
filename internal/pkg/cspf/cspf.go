// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"

	"github.com/nttcom/pola/internal/pkg/table"
)

type node struct {
	id          string
	calculated  bool
	cost        uint32
	prevNode    string
	nodeSegment table.Segment
}

func newNode(id string, cost uint32, nodeSeg table.Segment) *node {
	return &node{
		id:          id,
		cost:        cost,
		nodeSegment: nodeSeg,
	}
}

func Cspf(srcRouterId string, dstRouterId string, as uint32, metric table.MetricType, ted *table.LsTed) ([]table.Segment, error) {
	network := ted.Nodes[as]
	// TODO: update network information according to constraints
	segmentList, err := spf(srcRouterId, dstRouterId, metric, network)
	if err != nil {
		return nil, err
	}

	return segmentList, nil
}

func spf(srcRouterId string, dstRouterId string, metricType table.MetricType, network map[string]*table.LsNode) ([]table.Segment, error) {
	// Create a new starting node with cost 0 and add it to the calculating nodes
	startNodeSeg, err := network[srcRouterId].NodeSegment()
	if err != nil {
		return nil, err
	}
	startNode := newNode(srcRouterId, 0, startNodeSeg)
	startNode.calculated = false
	calculatingNodes := map[string]*node{srcRouterId: startNode}

	// Keep calculating the shortest path until the destination node is reached
	for {
		// Select the next node to calculate
		calcNodeId, err := nextNode(calculatingNodes)
		if err != nil {
			return nil, err
		}
		if calcNodeId == dstRouterId {
			break
		}

		// Calculate the cost of each link from the selected node
		for _, link := range network[calcNodeId].Links {
			metric, err := link.Metric(metricType)
			if err != nil {
				return nil, err
			}

			// If the remote node is already being calculated, update its cost if necessary
			if remoteNode, exists := calculatingNodes[link.RemoteNode.RouterId]; exists {
				if calculatingNodes[calcNodeId].cost+metric < remoteNode.cost {
					remoteNode.cost = calculatingNodes[calcNodeId].cost + metric
					remoteNode.prevNode = calcNodeId
				}
			} else {
				// If the remote node has not been calculated yet, create a new node for it and add it to the calculating nodes
				remoteNodeSeg, err := link.RemoteNode.NodeSegment()
				if err != nil {
					return nil, err
				}
				remoteNode := newNode(link.RemoteNode.RouterId, calculatingNodes[calcNodeId].cost+metric, remoteNodeSeg)
				remoteNode.prevNode = calcNodeId
				calculatingNodes[link.RemoteNode.RouterId] = remoteNode
			}
		}

		// Mark the selected node as calculated
		calculatingNodes[calcNodeId].calculated = true
	}

	// Generate the segment list from the shortest path calculation results
	segmentList := []table.Segment{}
	for pathNode := calculatingNodes[dstRouterId]; pathNode.id != srcRouterId; pathNode = calculatingNodes[pathNode.prevNode] {
		segmentList = append(segmentList, pathNode.nodeSegment)
	}

	// Reverse the order of the segment list
	for i, j := 0, len(segmentList)-1; i < j; i, j = i+1, j-1 {
		segmentList[i], segmentList[j] = segmentList[j], segmentList[i]
	}

	return segmentList, nil
}

// nextNode returns the Id of the next node to calculate.
func nextNode(calculatingNodes map[string]*node) (string, error) {
	nextNodeId := ""
	for nodeId, node := range calculatingNodes {
		if node.calculated {
			continue
		}
		if nextNodeId == "" || calculatingNodes[nextNodeId].cost > node.cost {
			nextNodeId = nodeId
		}
	}
	if nextNodeId == "" {
		return "", errors.New("next node not found")
	}
	return nextNodeId, nil
}
