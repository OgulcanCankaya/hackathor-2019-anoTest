package main

import (
	"fmt"
	"os"

	"github.com/batuberksahin/hackathor/hackathor/ruleEngine/Controller"
	"github.com/batuberksahin/hackathor/hackathor/ruleEngine/Engine"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/subosito/gotenv"
)

func main() {
	gotenv.Load()

	db := initDB()
	db.AutoMigrate(&Engine.Baseline{})

	r := gin.Default()

	r.GET("/ping", Controller.Ping)

	r.POST("/http", Controller.Http)

	r.Run(os.Getenv("APP_PORT"))
}

func initEnv() {
	gotenv.Load()
}

func initDB() (db *gorm.DB) {
	initEnv()

	db, err := gorm.Open("postgres", "host="+os.Getenv("DB")+" port=5432 user="+os.Getenv("DB_USER")+" dbname= "+os.Getenv("DB_NAME")+" password="+os.Getenv("DB_PASSWORD"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return db
}
