package http

import (
	"config_analyze/internal/domain"
	"config_analyze/internal/processor"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/valyala/fasthttp"
)

type Server struct {
	processor processor.Processor
	server    *fasthttp.Server
}

func New(processor processor.Processor) *Server {
	server := &fasthttp.Server{}
	return &Server{
		processor: processor,
		server:    server,
	}
}

func (s *Server) Start(port int) error {
	s.server.Handler = s.handlerCheck
	log.Printf("start listening http-server at %d port\n", port)
	return s.server.ListenAndServe(fmt.Sprintf("localhost:%d", port))
}

func (s *Server) Stop() error {
	log.Println("stop http-server")
	return s.server.Shutdown()
}

func (s *Server) handlerCheck(ctx *fasthttp.RequestCtx) {
	if string(ctx.Request.Header.Method()) != http.MethodPost || string(ctx.Request.URI().Path()) != "/check" {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}
	data := ctx.Request.Body()
	res, err := s.processor.Process(data)
	if err != nil {
		log.Printf("failed to process data: %s\n", err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	responseBody, err := json.Marshal(domain.ConvertResultToResponse(res))
	if err != nil {
		log.Printf("failed to marshal result: %s\n", err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseBody)
}
