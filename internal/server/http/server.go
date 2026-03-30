package http

import (
	"config_analyze/internal/processor/vulnerability"
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

type Server struct {
}

func New() *Server {
	return &Server{}
}

func (s *Server) Start(port int) error {
	log.Printf("start listening http-server at %d port\n", port)
	return fasthttp.ListenAndServe(fmt.Sprintf("localhost:%d", port), func(ctx *fasthttp.RequestCtx) {
		data := ctx.Request.Body()
		res, err := vulnerability.New().Process(data)
		if err != nil {
			log.Printf("failed to process data: %s\n", err.Error())
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(res)
	})
}
