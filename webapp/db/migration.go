package db

import (
	"os"

	"github.com/batuberksahin/hackathor/hackathor/webapp/models"
	"github.com/jinzhu/gorm"
)

func CreateDb() *gorm.DB {

	dbToUse, err := gorm.Open("postgres", "host="+os.Getenv("DB")+" port="+os.Getenv("DB_PORT")+" user="+os.Getenv("DB_USER")+" dbname="+os.Getenv("DB_NAME")+" password="+os.Getenv("DB_PASSWORD"))
	if err != nil {
		os.Exit(3)
	}

	return dbToUse
}

func MigrateDb(dbToUse *gorm.DB) {
	dbToUse.AutoMigrate(&models.Incident{})
	return
}
