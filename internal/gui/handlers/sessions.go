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

// GetSessions handles GET /api/sessions
func GetSessions(client pb.PCEServiceClient, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Handling GET /api/sessions request")

		sessions, err := grpcClient.GetSessions(client)
		if err != nil {
			logger.Error("Failed to get sessions", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve sessions",
			})
			return
		}

		logger.Info("Successfully retrieved sessions", zap.Int("count", len(sessions)))
		c.JSON(http.StatusOK, gin.H{
			"sessions": sessions,
		})
	}
}
