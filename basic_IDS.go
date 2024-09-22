/**
 * Basic Intrusion Detection System
 *
 * Author: Ryan Feneley
 * Date: September 2024
 *
 */

 package main

 import (
	 "bufio"
	 "fmt"
	 "log"
	 "os"
	 "strings"
	 "time"
 )
 
 type LogEntry struct {
	 Timestamp time.Time
	 Message   string
 }
 
 type Alert struct {
	 Timestamp time.Time
	 Message   string
 }
 
 const logFilePath = "ids_log.txt"
 const alertFilePath = "ids_alerts.txt"
 
 // threshold for failed login attempts
 const FailedLoginThreshold = 5
 
 //monitors a log file for suspicious activity
 func MonitorLogs() {
	 file, err := os.Open("system.log") //REPLACE WITH DESIRED LOG FILE
	 if err != nil {
		 log.Fatalf("failed to open log file: %v", err)
	 }
	 defer file.Close()
 
	 reader := bufio.NewReader(file)
	 failedLoginCount := 0
 
	 for {
		 line, err := reader.ReadString('\n')
		 if err != nil {
			 if err.Error() != "EOF" {
				 log.Printf("error reading log file: %v", err)
			 }
			 break
		 }
 
		 if strings.Contains(line, "Failed login") {
			 failedLoginCount++
			 if failedLoginCount >= FailedLoginThreshold {
				 alert := Alert{
					 Timestamp: time.Now(),
					 Message:   fmt.Sprintf("Alert: Too many failed login attempts detected! Count: %d", failedLoginCount),
				 }
				 logAlert(alert)
				 failedLoginCount = 0 // Reset counter after alert
			 }
		 }
	 }
 }
 
 // logAlert logs the alert to a file
 func logAlert(alert Alert) {
	 alertFile, err := os.OpenFile(alertFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	 if err != nil {
		 log.Fatalf("failed to open alert log file: %v", err)
	 }
	 defer alertFile.Close()
 
	 _, err = alertFile.WriteString(fmt.Sprintf("%s: %s\n", alert.Timestamp.Format(time.RFC3339), alert.Message))
	 if err != nil {
		 log.Printf("failed to write alert to log file: %v", err)
	 }
 }
 
 // logActivity logs the IDS activity to a file
 func logActivity(entry LogEntry) {
	 logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	 if err != nil {
		 log.Fatalf("failed to open log file: %v", err)
	 }
	 defer logFile.Close()
 
	 _, err = logFile.WriteString(fmt.Sprintf("%s: %s\n", entry.Timestamp.Format(time.RFC3339), entry.Message))
	 if err != nil {
		 log.Printf("failed to write log activity to file: %v", err)
	 }
 }
 
 func main() {
	 // Simulate monitoring logs
	 for {
		 MonitorLogs()
		 time.Sleep(10 * time.Second)
	 }
 }
 