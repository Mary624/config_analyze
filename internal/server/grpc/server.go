package grpc

import (
	"config_analyze/api/proto/checker"
	"config_analyze/internal/processor"
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
)

type Server struct {
	server    *grpc.Server
	processor processor.Processor
	checker.UnimplementedVulnerabilityCheckerServer
}

func New(processor processor.Processor) *Server {
	return &Server{
		processor: processor,
		server:    grpc.NewServer(),
	}
}

func (s *Server) Start(port int) error {
	listen, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}
	checker.RegisterVulnerabilityCheckerServer(s.server, s)
	log.Printf("gRPC server listening on port %d", port)
	return s.server.Serve(listen)
}

func (s *Server) Stop() {
	log.Println("stop grpc-server")
	s.server.GracefulStop()
}
func (s *Server) CheckConfig(ctx context.Context, req *checker.CheckRequest) (*checker.CheckResponse, error) {
	resBytes, err := s.processor.Process(req.Data)
	if err != nil {
		log.Printf("failed to process data: %s\n", err.Error())
		return nil, err
	}

	resultResponse := make([]*checker.Vulnerability, 0, len(resBytes))
	for _, v := range resBytes {
		if v.Field == nil {
			continue
		}
		resultResponse = append(resultResponse, &checker.Vulnerability{
			Level:          v.Field.Level().String(),
			Recommendation: v.Field.Info(v.WrongValue),
		})
	}

	return &checker.CheckResponse{Vulnerabilities: resultResponse}, nil
}
