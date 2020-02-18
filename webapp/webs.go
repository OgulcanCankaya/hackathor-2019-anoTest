package main

import (
	"github.com/batuberksahin/hackathor/hackathor/webapp/controllers"
	"github.com/gin-gonic/gin"
)

func initRouter(router *gin.Engine) {
	api := router.Group("/api")
	{
		api.GET("/", controllers.GetAllNotProcessedThreats)
		api.GET("/all", controllers.GetAllThreats)
		api.GET("/numbers", controllers.GetThreatNumbers)
		api.GET("/humanThreats", controllers.GetHumanCausedThreats)
		api.GET("/serverThreats", controllers.GetServerCausedThreats)
		api.GET("/processed/:id", controllers.UpdateThreat)
		api.GET("/get/:id", controllers.GetThreat)
		api.POST("/createThreat", controllers.CreateThreat)
	}
	router.GET("/", controllers.GetIndex)

}
