# Basic Intrusion Detection System (IDS)

## Description
This project implements a simple Intrusion Detection System (IDS) in Go. The IDS monitors logs for suspicious activity, such as too many failed login attempts, and triggers alerts when predefined thresholds are exceeded. It is designed to be a lightweight and simple example of how an IDS works.

## Features
- Monitors log files (e.g., failed login attempts)
- Triggers alerts when suspicious patterns are detected
- Logs activity and alerts to separate files for review
- Easy to customize for additional intrusion detection rules

## Installation
1. Clone the repository to your local machine:
   \\\
   git clone <repository-url>
   \\\
2. Navigate to the project directory:
   \\\
   cd basic-ids
   \\\
3. Run the IDS program:
   \\\
   go run main.go
   \\\

## Usage
1. Modify the \system.log\ file to simulate failed login attempts or other events.
2. The IDS will monitor the log and trigger an alert if too many failed attempts are detected.
3. Alerts are logged in \ids_alerts.txt\, and regular activity is logged in \ids_log.txt\.
