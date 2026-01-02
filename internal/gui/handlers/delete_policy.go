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

// DeletePolicyRequest represents the request body for deleting an SR policy
type DeletePolicyRequest struct {
	PeerAddr string `json:"peer_addr" binding:"required"`
	DstAddr  string `json:"dst_addr" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Color    uint32 `json:"color" binding:"required"`
	ASN      uint32 `json:"asn" binding:"required"`
}

// DeletePolicy handles DELETE /api/policies
func DeletePolicy(client pb.PCEServiceClient, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Handling DELETE /api/policies request")

		var req DeletePolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Error("Invalid request body", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request body: " + err.Error(),
			})
			return
		}

		// Parse addresses
		peerAddr, err := netip.ParseAddr(req.PeerAddr)
		if err != nil {
			logger.Error("Invalid peer address", zap.String("addr", req.PeerAddr), zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid peer address: " + err.Error(),
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

		// Create SR Policy for deletion (only need identifying fields)
		srPolicy := &pb.SRPolicy{
			PcepSessionAddr: peerAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			PolicyName:      req.Name,
			Color:           req.Color,
		}

		// Create gRPC request
		grpcReq := &pb.DeleteSRPolicyRequest{
			SrPolicy: srPolicy,
			Asn:      req.ASN,
		}

		// Call gRPC
		if err := grpcClient.DeleteSRPolicy(client, grpcReq); err != nil {
			logger.Error("Failed to delete SR policy", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete SR policy: " + err.Error(),
			})
			return
		}

		logger.Info("Successfully deleted SR policy",
			zap.String("name", req.Name),
			zap.String("peer", req.PeerAddr),
			zap.Uint32("color", req.Color))

		c.JSON(http.StatusOK, gin.H{
			"message": "SR policy deleted successfully",
		})
	}
}
