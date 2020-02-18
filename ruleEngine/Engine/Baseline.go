package Engine

import (
	"fmt"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Baseline struct {
	gorm.Model
	Traffic             int
	UserAgent           string
	UserAgentCount      uint
	IPCount             uint
	ContentType         string
	ContentTypeCount    uint
	Traffic_Date        string
	Host                string
	HostCount           uint
	Referer             string
	RefererCount        uint
	AcceptLanguage      string
	AcceptLanguageCount uint
}

func GetBaseline() (bsl Baseline) {
	db := initDB()
	var baselinee Baseline
	db.First(&baselinee)
	return baselinee
}

func initDB() (db *gorm.DB) {
	fmt.Println(os.Getenv("DB"))
	db, err := gorm.Open("postgres", "host="+os.Getenv("DB")+" port=5432 user="+os.Getenv("DB_USER")+" dbname= "+os.Getenv("DB_NAME")+" password="+os.Getenv("DB_PASSWORD"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return db
}
