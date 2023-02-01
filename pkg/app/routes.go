package app

import "github.com/gin-gonic/gin"

func (s *Server) Routes() *gin.Engine {
	router := s.router

	v1 := router.Group("v1")
	{
		v1.GET("/ready", s.HealthCheck())
		db := v1.Group("/DBCommand")
		{
			db.POST("", s.DbCommand())
		}
		cve := v1.Group("/scanImage")
		{
			cve.POST("", s.CreateCVE())
		}
	}

	return router
}
