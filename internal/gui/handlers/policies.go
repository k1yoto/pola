// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package handlers

import (
	"net/http"

	pb "github.com/nttcom/pola/api/pola/v1"
	grpcClient "github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// GetPolicies handles GET /api/policies
func GetPolicies(client pb.PCEServiceClient, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Handling GET /api/policies request")

		policies, err := grpcClient.GetSRPolicyList(client)
		if err != nil {
			logger.Error("Failed to get policies", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve policies",
			})
			return
		}

		logger.Info("Successfully retrieved policies", zap.Int("peer_count", len(policies)))
		c.JSON(http.StatusOK, gin.H{
			"policies": policies,
		})
	}
}
