package grpc

type Server struct {
}

func New() *Server {
	return &Server{}
}

func (s *Server) Start(port int) error {
	return nil
}
