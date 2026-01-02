// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package client

import (
	"context"
	"fmt"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	maxRetries     = 5
	retryDelay     = 2 * time.Second
	requestTimeout = 10 * time.Second
)

// Client manages gRPC connection to polad server
type Client struct {
	conn   *grpc.ClientConn
	client pb.PCEServiceClient
	logger *zap.Logger
}

// NewClient creates a new gRPC client with retry logic
func NewClient(address string, logger *zap.Logger) (*Client, error) {
	var conn *grpc.ClientConn
	var err error

	// Retry connection logic
	for i := 0; i < maxRetries; i++ {
		logger.Info("Attempting to connect to polad",
			zap.String("address", address),
			zap.Int("attempt", i+1),
			zap.Int("max_retries", maxRetries),
		)

		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		conn, err = grpc.DialContext(ctx,
			address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		cancel()

		if err == nil {
			logger.Info("Successfully connected to polad", zap.String("address", address))
			break
		}

		logger.Warn("Failed to connect to polad",
			zap.String("address", address),
			zap.Error(err),
			zap.Duration("retry_delay", retryDelay),
		)

		if i < maxRetries-1 {
			time.Sleep(retryDelay)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to polad after %d retries: %w", maxRetries, err)
	}

	return &Client{
		conn:   conn,
		client: pb.NewPCEServiceClient(conn),
		logger: logger,
	}, nil
}

// GetClient returns the gRPC client
func (c *Client) GetClient() pb.PCEServiceClient {
	return c.client
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		c.logger.Info("Closing gRPC connection")
		return c.conn.Close()
	}
	return nil
}
