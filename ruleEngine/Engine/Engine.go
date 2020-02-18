package Engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Rule struct {
	RuleName string
	Content  string
}

type Condition struct {
	Name        string
	NameString  string
	History     bool
	Dir         string
	Headers     []Header
	Normal      string
	Anomaly     string
	Description string
	RiskLevel   int
}

type Header struct {
	Key   string
	Value string
}

type Req struct {
	Method      string `json:"Method"`
	Dir         string `json:"Dir"`
	HTTPVersion string `json:"HTTPVersion"`
	Headers     []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Headers"`
	Content string `json:"Content"`
	SrcIP   string `json:"SrcIP"`
	DstIP   string `json:"DstIP"`
	SrcMac  string `json:"SrcMac"`
	DstMac  string `json:"DstMac"`
}

type Counter struct {
	Key   string
	Count int
}

type PostData struct {
	Name            string    `json:"Name"`
	IncidentTime    time.Time `json:"IncidentTime"`
	ImportanceLevel int       `json:"ImportanceLevel"`
	Description     string    `json:"Description"`
	Repetition      int       `json:"Repetition"`
	Prevention      string    `json:"Prevention"`
	Processed       int       `json:"Processed"`
	CauseType       string    `json:"CauseType"`
	SrcIP           string    `json:"SrcIP"`
	SrcMac          string    `json:"SrcMac"`
}

var Requests []Req

// INTERNAL COUNTERS
var traffic_counter int = 0

// var useragent_counter int = 0
// var contenttype_counter int = 0
// var host_counter int = 0
// var referer_counter int = 0
// var acceptlanguage_counter int = 0
// var from_counter int = 0

// var traffic_counter []Counter
var IP_counter []Counter
var Useragent_counter []Counter
var Contenttype_counter []Counter
var Host_counter []Counter
var Referer_counter []Counter
var Acceptlanguage_counter []Counter

var start time.Time

func init() {
	fmt.Println("--> Rule Engine Started.")
	start = time.Now()
}

func Run(data string) {
	fmt.Println("Rule engine -> ")

	rules := ReadRules()

	var req Req
	_ = json.Unmarshal([]byte(data), &req)

	Requests = append(Requests, req)

	// _ = json.Unmarshal([]byte(data), &Requests)

	if time.Since(start) > 15*time.Second {
		start = time.Now()

		traffic_counter = 0
		IP_counter = []Counter{}
		Useragent_counter = []Counter{}
		Contenttype_counter = []Counter{}
		Host_counter = []Counter{}
		Referer_counter = []Counter{}
		Acceptlanguage_counter = []Counter{}
	}

	updateCounters()
	checkRules(data, rules)
}

func checkRules(data string, rules []Rule) {
	baseline := GetBaseline()

	ipFlag := false
	traficFlag := false
	useragentFlag := false
	contenttypeFlag := false
	hostFlag := false
	refererFlag := false
	acceptLanguageFlag := false

	for _, rule := range rules {
		var condition Condition

		parseRule(&rule, &condition)

		for _, request := range Requests {

			// BASELINE MODU KAPALIYSA
			if !condition.History {
				// HEADERS CHECK
				for _, condHeader := range condition.Headers {
					for _, reqHeader := range request.Headers {
						if reqHeader.Key == condHeader.Key {
							re := regexp.MustCompile(`(?m)` + condHeader.Key)

							RuleHeaderCondition := condHeader.Value

							if strings.Contains(condHeader.Value, "?") {
								RuleHeaderCondition = strings.Split(condHeader.Value, "?")[1]
							}

							isMatch := re.MatchString(RuleHeaderCondition)

							if isMatch || (strings.Contains(condHeader.Value, "!") && !isMatch) {
								// ALERT OLUŞTUR
								createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
								fmt.Println("DEBUG: " + reqHeader.Value + " = " + condHeader.Value)
							}
						}
					}
				}

				// DIR CHECK
				if request.Dir == condition.Dir {
					// ALERT OLUŞTUR
					createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
					fmt.Println("DEBUG: " + request.Dir + " = " + condition.Dir)
				}

			} else {
				lines := strings.Split(rule.Content, "\n")

				for _, line := range lines {
					// var normal string
					// var normalCount uint

					// var anomaly string
					// var anomalyCount uint

					if strings.Contains(line, "anomaly") {
						normalLine := strings.Split(line, "=")[1]
						wantedBaseline := strings.Split(normalLine, "_")[1]

						if strings.Contains(wantedBaseline, "traffic") {
							normal, _ := strconv.Atoi(strings.Split(wantedBaseline, "?")[1])

							if traffic_counter > baseline.Traffic+baseline.Traffic*normal/100 {
								if !traficFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: TRAFIK LIMITI AŞILDI NORMAL:", baseline.Traffic+baseline.Traffic*normal/100, "Anormal:", traffic_counter)
									traficFlag = true
								}
							}

						} else if strings.Contains(wantedBaseline, "useragent") {
							temp := strings.Split(wantedBaseline, "?")[1]
							normalKey := strings.Split(temp, ":")[0]
							percent, _ := strconv.Atoi(strings.Split(temp, ":")[1])

							counter := 0

							for _, element := range Useragent_counter {
								re := regexp.MustCompile(`(?m)` + normalKey)

								isMatch := re.MatchString(element.Key)

								if isMatch {
									counter++
								}
							}

							if counter > int(baseline.UserAgentCount)+int(baseline.UserAgentCount)*percent/100 {
								if !useragentFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: USER AGENT AŞILDI")
									useragentFlag = true
								}
							}

						} else if strings.Contains(wantedBaseline, "content-type") {
							temp := strings.Split(wantedBaseline, "?")[1]
							normalKey := strings.Split(temp, ":")[0]
							percent, _ := strconv.Atoi(strings.Split(temp, ":")[1])

							counter := 0

							for _, element := range Contenttype_counter {
								re := regexp.MustCompile(`(?m)` + normalKey)

								isMatch := re.MatchString(element.Key)

								if isMatch {
									counter++
								}
							}

							if counter > int(baseline.ContentTypeCount)+int(baseline.ContentTypeCount)*percent/100 {
								if !contenttypeFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: CONTENT TYPE AŞILDI")
									contenttypeFlag = true
								}
							}
						} else if strings.Contains(wantedBaseline, "host") {
							temp := strings.Split(wantedBaseline, "?")[1]
							normalKey := strings.Split(temp, ":")[0]
							percent, _ := strconv.Atoi(strings.Split(temp, ":")[1])

							counter := 0

							for _, element := range Contenttype_counter {
								re := regexp.MustCompile(`(?m)` + normalKey)

								isMatch := re.MatchString(element.Key)

								if isMatch {
									counter++
								}
							}

							if counter > int(baseline.HostCount)+int(baseline.HostCount)*percent/100 {
								if !hostFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: HOST AŞILDI")
									hostFlag = true
								}
							}
						} else if strings.Contains(wantedBaseline, "referer") {
							temp := strings.Split(wantedBaseline, "?")[1]
							normalKey := strings.Split(temp, ":")[0]
							percent, _ := strconv.Atoi(strings.Split(temp, ":")[1])

							counter := 0

							for _, element := range Referer_counter {
								re := regexp.MustCompile(`(?m)` + normalKey)

								isMatch := re.MatchString(element.Key)

								if isMatch {
									counter++
								}
							}

							if counter > int(baseline.RefererCount)+int(baseline.RefererCount)*percent/100 {
								if !refererFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: REFERER AŞILDI")
									refererFlag = true
								}
							}
						} else if strings.Contains(wantedBaseline, "accept-language") {
							temp := strings.Split(wantedBaseline, "?")[1]
							normalKey := strings.Split(temp, ":")[0]
							percent, _ := strconv.Atoi(strings.Split(temp, ":")[1])

							counter := 0

							for _, element := range Acceptlanguage_counter {
								re := regexp.MustCompile(`(?m)` + normalKey)

								isMatch := re.MatchString(element.Key)

								if isMatch {
									counter++
								}
							}

							if counter > int(baseline.AcceptLanguageCount)+int(baseline.AcceptLanguageCount)*percent/100 {
								if !acceptLanguageFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: ACCEPT LANGUAGE AŞILDI")
									acceptLanguageFlag = true
								}
							}
						} else if strings.Contains(wantedBaseline, "iplimit") {
							normal, _ := strconv.Atoi(strings.Split(wantedBaseline, "?")[1])

							counter := 0

							for _, element := range IP_counter {
								if request.SrcIP == element.Key {
									counter++
								}
							}

							if counter > int(baseline.IPCount)+int(baseline.IPCount)*normal/100 {
								if !ipFlag {
									createIncident(condition.NameString, condition.RiskLevel, condition.Description, "", request.DstIP, request.DstMac)
									fmt.Println("DEBUG: IP LIMITI AŞILDI NORMAL: ", request.DstIP)
									ipFlag = true
								}
							}

						}
					}

					// if strings.Contains(line, "normal") {
					// 	anomalyLine := strings.Split(line, "=")[1]
					// 	wantedBaseline := strings.Split(anomalyLine, "_")[1]
					// 	fmt.Println("Wanted Base Line: " + wantedBaseline)

					// }
				}
			}

		}

	}
	// REQUESTLERI SIFIRLA
	Requests = []Req{}
	ipFlag = false
	traficFlag = false
	useragentFlag = false
	contenttypeFlag = false
	hostFlag = false
	refererFlag = false
	acceptLanguageFlag = false
}

func updateCounters() {
	for _, request := range Requests {
		traffic_counter++

		var ip_count Counter
		ip_count.Key = request.SrcIP
		ip_count.Count++

		IP_counter = append(IP_counter, ip_count)

		for _, header := range request.Headers {
			if strings.Contains(header.Key, "User-Agent") {
				var useragent_count Counter
				useragent_count.Key = header.Value
				useragent_count.Count++

				Useragent_counter = append(Useragent_counter, useragent_count)
			} else if strings.Contains(header.Key, "Content-Type") {
				var contenttype_count Counter
				contenttype_count.Key = header.Value
				contenttype_count.Count++

				Contenttype_counter = append(Contenttype_counter, contenttype_count)
			} else if strings.Contains(header.Key, "Host") {
				var host_count Counter
				host_count.Key = header.Value
				host_count.Count++

				Host_counter = append(Host_counter, host_count)
			} else if strings.Contains(header.Key, "Referer") {
				var referer_count Counter
				referer_count.Key = header.Value
				referer_count.Count++

				Referer_counter = append(Referer_counter, referer_count)
			} else if strings.Contains(header.Key, "Accept-Language") {
				var acceptlanguage_count Counter
				acceptlanguage_count.Key = header.Value
				acceptlanguage_count.Count++

				Acceptlanguage_counter = append(Acceptlanguage_counter, acceptlanguage_count)
			}
		}
	}
}

func parseRule(rule *Rule, condition *Condition) {
	lines := strings.Split(rule.Content, "\n")

	// fmt.Println("name: ", condition.Name, "a")

	for _, line := range lines {
		if condition.Name != "  " && condition.NameString != "  " {
			if strings.Contains(line, "name") {
				nameLine := strings.Split(line, ", ")

				condition.Name = nameLine[1]
				condition.NameString = nameLine[2]

				// fmt.Println(condition)
			}
		}

		if strings.Contains(line, "#") {
			hashLine := strings.Split(line, "=")

			if hashLine[1] == "true" {
				condition.History = true
			} else {
				condition.History = false
			}

			// fmt.Println(condition)
		}

		if strings.Contains(line, "normal") && !strings.Contains(line, "#") {
			normalLine := strings.Split(line, "=")

			condition.Normal = normalLine[1]
		}

		if strings.Contains(line, "anomaly") && !strings.Contains(line, "#") {
			anomalyLine := strings.Split(line, "=")

			condition.Anomaly = anomalyLine[1]
		}

		if strings.Contains(line, "description") && !strings.Contains(line, "#") {
			descriptionLine := strings.Split(line, "=")

			condition.Description = descriptionLine[1]
		}

		if strings.Contains(line, "risk_level") && !strings.Contains(line, "#") {
			risk_levelLine := strings.Split(line, "=")

			condition.RiskLevel, _ = strconv.Atoi(risk_levelLine[1])
		}

		if strings.Contains(line, "dir") && !strings.Contains(line, "#") {
			dirLine := strings.Split(line, "=")

			condition.Dir = dirLine[1]
		}
	}

	var re = regexp.MustCompile(`(?m)header=header_(.*?):(.*?)\n`)

	headerLine := re.FindAllStringSubmatch(rule.Content, -1)

	for _, header := range headerLine {
		var toHeader Header

		toHeader.Key = header[1]
		toHeader.Value = header[2]

		condition.Headers = append(condition.Headers, toHeader)
	}

}

func createIncident(name string, importanceLevel int, description string, prevention string, ip string, mac string) {
	postData := PostData{
		Name:            name,
		ImportanceLevel: importanceLevel,
		Description:     description,
		Prevention:      prevention,
		IncidentTime:    time.Now(),
		Processed:       0,
		CauseType:       "Non-Defined",
		SrcIP:           ip,
		SrcMac:          mac,
	}

	a, _ := json.Marshal(postData)
	_, _ = http.Post("http://localhost:3132/api/createThreat", "application/json", bytes.NewBuffer(a))
}

func ReadRules() []Rule {
	files, err := ioutil.ReadDir(os.Getenv("RULE_SET"))

	var rules []Rule

	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		data, _ := ioutil.ReadFile(os.Getenv("RULE_SET") + "/" + f.Name())

		var rule Rule

		rule.RuleName = f.Name()
		rule.Content = string(data)

		rules = append(rules, rule)
	}

	return rules
}
