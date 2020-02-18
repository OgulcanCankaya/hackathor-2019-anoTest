package models

import (
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Incident struct {
	gorm.Model
	Name            string    `json:"Name"`
	IncidentTime    time.Time `json:"IncidentTime"`
	ImportanceLevel int       `json:"ImportanceLevel"`
	Description     string    `json:"Description"`
	Repetition      int       `json:"Repetition"`
	Prevention      string    `json:"Prevention"`
	Processed       int8      `gorm:"default:0" json:"Processed"`
	CauseType       string    `json:"CauseType"`
	SrcIP           string    `json:"SrcIP"`
	SrcMac          string    `json:"SrcMac"`
}
