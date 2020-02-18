webs.go ---------------> Router file



You can use  controllers/dashboard.go for route controllers




















Api_name
Sample_json


THIS RETURNS TO YOU ALL OF THE NOT PROCESSED INCIDENTS
--------------------
/api/
--------------------
[{"ID":1,"CreatedAt":"2019-11-30T20:05:51.349156+03:00","UpdatedAt":"2019-11-30T20:05:51.349156+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:05:51.348903+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":2,"CreatedAt":"2019-11-30T20:05:51.4275+03:00","UpdatedAt":"2019-11-30T20:05:51.4275+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":5,"CreatedAt":"2019-11-30T20:09:52.75502+03:00","UpdatedAt":"2019-11-30T20:09:52.75502+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:09:52.725992+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":6,"CreatedAt":"2019-11-30T20:09:52.763314+03:00","UpdatedAt":"2019-11-30T20:09:52.763314+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:09:52.725993+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":7,"CreatedAt":"2019-11-30T20:11:41.768742+03:00","UpdatedAt":"2019-11-30T20:11:41.768742+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.76845+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":8,"CreatedAt":"2019-11-30T20:11:41.830573+03:00","UpdatedAt":"2019-11-30T20:11:41.830573+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.768451+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":9,"CreatedAt":"2019-11-30T20:11:41.889084+03:00","UpdatedAt":"2019-11-30T20:11:41.889084+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.768451+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":10,"CreatedAt":"2019-11-30T20:13:17.614346+03:00","UpdatedAt":"2019-11-30T20:13:17.614346+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614014+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":11,"CreatedAt":"2019-11-30T20:13:17.630055+03:00","UpdatedAt":"2019-11-30T20:13:17.630055+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614024+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":12,"CreatedAt":"2019-11-30T20:13:17.638313+03:00","UpdatedAt":"2019-11-30T20:13:17.638313+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614024+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":13,"CreatedAt":"2019-11-30T20:13:45.653332+03:00","UpdatedAt":"2019-11-30T20:13:45.653332+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:45.652937+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":14,"CreatedAt":"2019-11-30T20:13:45.71486+03:00","UpdatedAt":"2019-11-30T20:13:45.71486+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:45.652939+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":3,"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":16,"CreatedAt":"2019-11-30T22:42:45.753062+03:00","UpdatedAt":"2019-11-30T22:42:45.753062+03:00","DeletedAt":null,"Name":"","IncidentTime":"0001-01-01T01:55:52+01:55","ImportanceLevel":0,"Description":"","Repetition":0,"Prevention":"","Processed":0,"CauseType":""},{"ID":17,"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DODISSS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":"Human"}]




RETURNS ALL THE THREATS BOTH PROCESSED AND NOT PROCESSED
---------------------
/api/all
---------------------
[{"ID":1,"CreatedAt":"2019-11-30T20:05:51.349156+03:00","UpdatedAt":"2019-11-30T20:05:51.349156+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:05:51.348903+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":2,"CreatedAt":"2019-11-30T20:05:51.4275+03:00","UpdatedAt":"2019-11-30T20:05:51.4275+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":5,"CreatedAt":"2019-11-30T20:09:52.75502+03:00","UpdatedAt":"2019-11-30T20:09:52.75502+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:09:52.725992+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":6,"CreatedAt":"2019-11-30T20:09:52.763314+03:00","UpdatedAt":"2019-11-30T20:09:52.763314+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:09:52.725993+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":7,"CreatedAt":"2019-11-30T20:11:41.768742+03:00","UpdatedAt":"2019-11-30T20:11:41.768742+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.76845+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":8,"CreatedAt":"2019-11-30T20:11:41.830573+03:00","UpdatedAt":"2019-11-30T20:11:41.830573+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.768451+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":9,"CreatedAt":"2019-11-30T20:11:41.889084+03:00","UpdatedAt":"2019-11-30T20:11:41.889084+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:11:41.768451+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":10,"CreatedAt":"2019-11-30T20:13:17.614346+03:00","UpdatedAt":"2019-11-30T20:13:17.614346+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614014+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":11,"CreatedAt":"2019-11-30T20:13:17.630055+03:00","UpdatedAt":"2019-11-30T20:13:17.630055+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614024+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":12,"CreatedAt":"2019-11-30T20:13:17.638313+03:00","UpdatedAt":"2019-11-30T20:13:17.638313+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:17.614024+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":13,"CreatedAt":"2019-11-30T20:13:45.653332+03:00","UpdatedAt":"2019-11-30T20:13:45.653332+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:45.652937+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":14,"CreatedAt":"2019-11-30T20:13:45.71486+03:00","UpdatedAt":"2019-11-30T20:13:45.71486+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:45.652939+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":15,"CreatedAt":"2019-11-30T20:13:45.723065+03:00","UpdatedAt":"2019-11-30T20:13:45.723065+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:13:45.65294+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":1,"CauseType":""},{"ID":4,"CreatedAt":"2019-11-30T20:09:52.726225+03:00","UpdatedAt":"2019-11-30T20:09:52.726225+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-30T20:09:52.725992+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":1,"CauseType":""},{"ID":3,"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":""},{"ID":16,"CreatedAt":"2019-11-30T22:42:45.753062+03:00","UpdatedAt":"2019-11-30T22:42:45.753062+03:00","DeletedAt":null,"Name":"","IncidentTime":"0001-01-01T01:55:52+01:55","ImportanceLevel":0,"Description":"","Repetition":0,"Prevention":"","Processed":0,"CauseType":""},{"ID":17,"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DODISSS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":"Human"}]








RETURNS THE NUMBERS NEEDED FOR THE DASHBOARD
--------------------------
/api/numbers
--------------------------
{"ThreatsIn24Hours":14,"TotalThreats":17,"UnprocessedThreats":15,"level1":0,"level2":0,"level3":0,"level4":16,"level5":0}





/api/humanThreats
/api/serverThreats
BU İKİSİNDE KÜÇÜK Bİ SIKINTI VAR ANLAYAMADIM






THIS ENDPOINT UPDATES THE INCIDENT WITH GIVEN ID (:id) TO PROCESSED
-----------------------
/api/processed/:id
-----------------------
{"message":"Success"}



THIS ENDPOINT RETURNS THE INCIDENT WITH GIVEN ID (:id)
-----------------------
/api/get/:id
-----------------------
{"ID":3,"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DOS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":1,"CauseType":""}











THIS ENDPOINT CREATES AN INCIDENT
------------------------------
/api/createThreat
------------------------------
EXAMPLE JSON BODY TO SEND:

{"CreatedAt":"2019-11-30T20:05:51.435727+03:00","UpdatedAt":"2019-11-30T20:05:51.435727+03:00","DeletedAt":null,"Name":"DODISSS","IncidentTime":"2019-11-25T20:05:51.348904+03:00","ImportanceLevel":4,"Description":"Distributed thing","Repetition":44,"Prevention":"just turn it off","Processed":0,"CauseType":"Human"}







