package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/batuberksahin/hackathor/hackathor/webapp/db"
	"github.com/batuberksahin/hackathor/hackathor/webapp/models"

	"github.com/gin-gonic/gin"
)

func GetAllNotProcessedThreats(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incidents []models.Incident
	dbToUse.Where("processed = ?", 0).Find(&Incidents)

	incidentsJSON, _ := json.Marshal(Incidents)
	c.String(http.StatusOK, string(incidentsJSON))

}

func GetAllThreats(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incidents []models.Incident
	dbToUse.Order("incident_time desc").Find(&Incidents)

	incidentsJSON, _ := json.Marshal(Incidents)
	c.String(http.StatusOK, string(incidentsJSON))

}
func GetAllHumanThreats(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incidents []models.Incident
	dbToUse.Where("cause_type = ?", "Human").Find(&Incidents)

	incidentsJSON, _ := json.Marshal(Incidents)
	c.String(http.StatusOK, string(incidentsJSON))

}
func GetAllServerThreats(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incidents []models.Incident
	dbToUse.Where("cause_type = ?", "Server").Find(&Incidents)

	incidentsJSON, _ := json.Marshal(Incidents)
	c.String(http.StatusOK, string(incidentsJSON))

}

func GetThreat(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()
	var Incident models.Incident
	dbToUse.First(&Incident, c.Params.ByName("id"))
	if Incident.ID == 0 {
		c.String(http.StatusNotFound, "Not found")
		return
	} else {
		jsonStr, _ := json.Marshal(&Incident)
		c.String(http.StatusOK, string(jsonStr))
	}

}
func GetThreatNumbers(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	numbers := make(map[string]int)
	var Incident models.Incident

	totalThreats := 0
	unprocessedThreats := 0
	level5 := 0
	level4 := 0
	level3 := 0
	level2 := 0
	level1 := 0
	threatsIn24Hour := 0

	dbToUse.Model(Incident).Count(&totalThreats)
	dbToUse.Model(Incident).Where("processed = ?", 0).Count(&unprocessedThreats)
	dbToUse.Model(Incident).Where("importance_level = ?", 5).Count(&level5)
	dbToUse.Model(Incident).Where("importance_level = ?", 4).Count(&level4)
	dbToUse.Model(Incident).Where("importance_level = ?", 3).Count(&level3)
	dbToUse.Model(Incident).Where("importance_level = ?", 2).Count(&level2)
	dbToUse.Model(Incident).Where("importance_level = ?", 1).Count(&level1)

	dbToUse.Model(Incident).Where("incident_time BETWEEN ? AND ?", time.Now().AddDate(0, 0, -1), time.Now()).Count(&threatsIn24Hour)

	numbers["TotalThreats"] = totalThreats
	numbers["UnprocessedThreats"] = unprocessedThreats
	numbers["level5"] = level5
	numbers["level4"] = level4
	numbers["level3"] = level3
	numbers["level2"] = level2
	numbers["level1"] = level1
	numbers["ThreatsIn24Hours"] = threatsIn24Hour

	numbersJSON, _ := json.Marshal(numbers)
	c.String(http.StatusOK, string(numbersJSON))
}
func UpdateThreat(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incident models.Incident
	dbToUse.First(&Incident, c.Params.ByName("id"))
	Incident.Processed = 1
	dbToUse.Save(Incident)
	c.JSON(http.StatusOK, gin.H{
		"message": "Success",
	})
}

func CreateThreat(c *gin.Context) {
	dbToUse := db.CreateDb()
	defer dbToUse.Close()

	var Incident models.Incident

	c.BindJSON(&Incident)
	fmt.Println(Incident.Name)
	Incident.Processed = 0
	dbToUse.Save(&Incident)
	c.JSON(http.StatusOK, gin.H{
		"message": "Success on Creation",
	})
}
