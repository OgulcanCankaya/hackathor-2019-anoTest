package Controller

import (
	"io/ioutil"

	"github.com/batuberksahin/hackathor/hackathor/ruleEngine/Engine"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func Ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func Http(c *gin.Context) {
	body := c.Request.Body

	if body == nil {
		c.JSON(404, gin.H{
			"message": "You need to send HTTP to us.",
		})
	} else {
		data, _ := ioutil.ReadAll(body)

		// fmt.Println(string(data))
		Engine.Run(string(data))
	}
}
