// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package handlers

import (
	"net/http"
	"net/netip"

	pb "github.com/nttcom/pola/api/pola/v1"
	grpcClient "github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CreatePolicyRequest represents the request body for creating an SR policy
type CreatePolicyRequest struct {
	PeerAddr     string   `json:"peer_addr" binding:"required"`
	Name         string   `json:"name" binding:"required"`
	SrcAddr      string   `json:"src_addr"`         // For explicit path
	DstAddr      string   `json:"dst_addr"`         // For explicit path
	SrcRouterID  string   `json:"src_router_id"`    // For dynamic path
	DstRouterID  string   `json:"dst_router_id"`    // For dynamic path
	Color        uint32   `json:"color" binding:"required"`
	Preference   uint32   `json:"preference"`
	SegmentList  []string `json:"segment_list"`
	IsDynamic    bool     `json:"is_dynamic"`
	MetricType   uint32   `json:"metric_type"`
	ASN          uint32   `json:"asn" binding:"required"`
}

// CreatePolicy handles POST /api/policies
func CreatePolicy(client pb.PCEServiceClient, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Handling POST /api/policies request")

		var req CreatePolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Error("Invalid request body", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request body: " + err.Error(),
			})
			return
		}

		// Convert segment list to Segment objects
		var segments []*pb.Segment
		if len(req.SegmentList) > 0 {
			for _, sid := range req.SegmentList {
				segments = append(segments, &pb.Segment{
					Sid: sid,
				})
			}
		}

		// Parse peer address (common for both explicit and dynamic)
		peerAddr, err := netip.ParseAddr(req.PeerAddr)
		if err != nil {
			logger.Error("Invalid peer address", zap.String("addr", req.PeerAddr), zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid peer address: " + err.Error(),
			})
			return
		}

		var srPolicy *pb.SRPolicy

		if req.IsDynamic {
			// Dynamic path: use SrcRouterID and DstRouterID
			if req.SrcRouterID == "" || req.DstRouterID == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "src_router_id and dst_router_id are required for dynamic path",
				})
				return
			}

			srPolicy = &pb.SRPolicy{
				PcepSessionAddr: peerAddr.AsSlice(),
				SrcRouterId:     req.SrcRouterID,
				DstRouterId:     req.DstRouterID,
				Color:           req.Color,
				PolicyName:      req.Name,
				Type:            pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
				SegmentList:     segments,
				Metric:          pb.MetricType(req.MetricType),
			}
		} else {
			// Explicit path: use SrcAddr and DstAddr
			if req.SrcAddr == "" || req.DstAddr == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "src_addr and dst_addr are required for explicit path",
				})
				return
			}

			if len(req.SegmentList) == 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "segment_list is required for explicit path",
				})
				return
			}

			srcAddr, err := netip.ParseAddr(req.SrcAddr)
			if err != nil {
				logger.Error("Invalid source address", zap.String("addr", req.SrcAddr), zap.Error(err))
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid source address: " + err.Error(),
				})
				return
			}

			dstAddr, err := netip.ParseAddr(req.DstAddr)
			if err != nil {
				logger.Error("Invalid destination address", zap.String("addr", req.DstAddr), zap.Error(err))
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid destination address: " + err.Error(),
				})
				return
			}

			srPolicy = &pb.SRPolicy{
				PcepSessionAddr: peerAddr.AsSlice(),
				SrcAddr:         srcAddr.AsSlice(),
				DstAddr:         dstAddr.AsSlice(),
				Color:           req.Color,
				PolicyName:      req.Name,
				Type:            pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
				SegmentList:     segments,
			}
		}

		// Create gRPC request
		grpcReq := &pb.CreateSRPolicyRequest{
			SrPolicy:    srPolicy,
			Asn:         req.ASN,
			PathCompute: req.IsDynamic,
		}

		// Call gRPC
		resp, err := grpcClient.CreateSRPolicy(client, grpcReq)
		if err != nil {
			logger.Error("Failed to create SR policy", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create SR policy: " + err.Error(),
			})
			return
		}

		logger.Info("Successfully created SR policy",
			zap.String("name", req.Name),
			zap.String("peer", req.PeerAddr))

		c.JSON(http.StatusCreated, gin.H{
			"message": "SR policy created successfully",
			"policy":  resp,
		})
	}
}
