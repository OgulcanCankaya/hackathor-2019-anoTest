package main

import (
	"github.com/batuberksahin/hackathor/hackathor/webapp/db"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/subosito/gotenv"
)

func main() {
	// Set the router as the default one shipped with Gin
	gotenv.Load()

	dbToUse := db.CreateDb()
	db.MigrateDb(dbToUse)
	defer dbToUse.Close()

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	router.Use(cors.New(config))
	//router.Use(cors.Default())

	router.LoadHTMLGlob("views/*")
	// Serve frontend static files

	// Setup route group for the API
	initRouter(router)

	// Start and run the server
	router.Run(":3132")
}
