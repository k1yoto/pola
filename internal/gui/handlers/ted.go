// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package handlers

import (
	"net/http"

	pb "github.com/nttcom/pola/api/pola/v1"
	grpcClient "github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TEDLinkResponse represents link data for JSON serialization with remote node info
type TEDLinkResponse struct {
	RemoteRouterID string             `json:"remote_router_id"`
	RemoteASN      uint32             `json:"remote_asn"`
	LocalIP        string             `json:"local_ip"`
	RemoteIP       string             `json:"remote_ip"`
	Metrics        []*table.Metric    `json:"metrics"`
	AdjSid         uint32             `json:"adj_sid"`
	Srv6EndXSID    *table.Srv6EndXSID `json:"srv6_endx_sid"`
}

// TEDNodeResponse represents node data for JSON serialization
type TEDNodeResponse struct {
	ASN        uint32              `json:"asn"`
	RouterID   string              `json:"router_id"`
	IsisAreaID string              `json:"isis_area_id"`
	Hostname   string              `json:"hostname"`
	SrgbBegin  uint32              `json:"srgb_begin"`
	SrgbEnd    uint32              `json:"srgb_end"`
	Links      []*TEDLinkResponse  `json:"links"`
	Prefixes   []*table.LsPrefix   `json:"prefixes"`
	SRv6SIDs   []*table.LsSrv6SID  `json:"srv6_sids"`
}

// TEDResponse represents the TED data for JSON serialization
type TEDResponse struct {
	ID    int                                    `json:"id"`
	Nodes map[uint32]map[string]*TEDNodeResponse `json:"nodes"`
}

// GetTED handles GET /api/ted
func GetTED(client pb.PCEServiceClient, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Handling GET /api/ted request")

		ted, err := grpcClient.GetTED(client)
		if err != nil {
			logger.Error("Failed to get TED", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve TED",
			})
			return
		}

		// Convert table.LsTED to TEDResponse
		response := convertTEDToResponse(ted)

		c.JSON(http.StatusOK, gin.H{
			"ted": response,
		})
	}
}

// convertTEDToResponse converts table.LsTED to TEDResponse with remote node information
func convertTEDToResponse(ted *table.LsTED) *TEDResponse {
	if ted == nil {
		return nil
	}

	responseNodes := make(map[uint32]map[string]*TEDNodeResponse)

	for asn, routerMap := range ted.Nodes {
		responseNodes[asn] = make(map[string]*TEDNodeResponse)

		for routerID, node := range routerMap {
			// Convert links with remote node information
			var links []*TEDLinkResponse
			if node.Links != nil {
				for _, link := range node.Links {
					var remoteRouterID string
					var remoteASN uint32

					// Get remote node info from the link's RemoteNode pointer
					if link.RemoteNode != nil {
						remoteRouterID = link.RemoteNode.RouterID
						remoteASN = link.RemoteNode.ASN
					}

					links = append(links, &TEDLinkResponse{
						RemoteRouterID: remoteRouterID,
						RemoteASN:      remoteASN,
						LocalIP:        link.LocalIP.String(),
						RemoteIP:       link.RemoteIP.String(),
						Metrics:        link.Metrics,
						AdjSid:         link.AdjSid,
						Srv6EndXSID:    link.Srv6EndXSID,
					})
				}
			}

			responseNodes[asn][routerID] = &TEDNodeResponse{
				ASN:        node.ASN,
				RouterID:   node.RouterID,
				IsisAreaID: node.IsisAreaID,
				Hostname:   node.Hostname,
				SrgbBegin:  node.SrgbBegin,
				SrgbEnd:    node.SrgbEnd,
				Links:      links,
				Prefixes:   node.Prefixes,
				SRv6SIDs:   node.SRv6SIDs,
			}
		}
	}

	return &TEDResponse{
		ID:    ted.ID,
		Nodes: responseNodes,
	}
}
