package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/TomOnTime/utfutil"
	"golang.org/x/sys/windows/registry"
)

/*
Read the Windows Registry to find the following:
	install location for Emsisoft Anti-Malware
	Display Name for the program
	GUID={5502032C-88C1-4303-99FE-B5CBD7684CEA}_is1
Read the a2settings.ini file. This file is in UTF-16 format so it required the use of utfutil
	Look for the [LastUpdated] section
	Read the Date= line in that section
	See if the last updated time is current (Need to define what "current" means)
	See if the EAM service is running
	Write/Update the JSON file %ProgramData%/CentraStage/AEMAgent/antivirus.json with the data
	JSON format:
	{"product":"Override Antivirus","running":true,"upToDate":true}
*/

func getValuesFromRegistry(eamGUID string) (string, string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+eamGUID, registry.QUERY_VALUE)
	if err != nil {
		// Log error
		return "", "", err
	}
	defer k.Close()

	// Populate the Product Name
	product, _, err := k.GetStringValue("DisplayName")
	if err != nil {
		// Log error
		return "", "", err
	}

	// Populate the Installation Location
	installLocation, _, err := k.GetStringValue("InstallLocation")
	if err != nil {
		// Log error
		return "", "", err
	}
	return product, installLocation, nil
}

func readDate(scanner utfutil.UTFScanCloser) (string, error) {
	for r := false; scanner.Scan() && !r; {
		line := scanner.Text()
		if strings.Contains(line, "LastUpdated") {
			r = true
			for i := false; !i && scanner.Scan(); {
				line := scanner.Text()
				if strings.HasPrefix(line, "Date=") {
					i = true
					lastUpdate := strings.Split(line, "=")[1]
					return lastUpdate, nil
				}
			}
		}
	}
	return "", scanner.Err()
}

func checkDate(lastUpdate int, d time.Duration) bool {
	updateTime := time.Unix(int64(lastUpdate), 0)
	_, offset := updateTime.Zone()
	updateTime = updateTime.Add(time.Second * time.Duration(-offset))
	if time.Since(updateTime) < d {
		return true
	}
	return false
}

func checkService(serviceName string) bool {

	/*
		I tried this command but it fails, so I had to split each word of the command into a separate argument
		cmd := exec.Command("wmic", "service where name='"+serviceName+" get state")
	*/

	extCMD := "wmic"
	extARG1 := "service"
	extARG2 := "where"
	extARG3 := "name='" + serviceName + "'"
	extARG4 := "get"
	extARG5 := "state"
	cmd := exec.Command(extCMD, extARG1, extARG2, extARG3, extARG4, extARG5)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error with WMIC")
		return false
	}
	if strings.Contains(out.String(), "Running") {
		return true
	}
	return false
}

//JSON format:
//	{"product":"Override Antivirus","running":true,"upToDate":true}

type aemJSON struct {
	Product  string `json: "product"`
	Running  bool   `json: "running"`
	UpToDate bool   `json: "upToDate"`
}

func main() {
	// This is the current GUID for Emsisoft Anti-Malware in the Windows Uninstall registry
	eamGUID := "{5502032C-88C1-4303-99FE-B5CBD7684CEA}_is1"

	// This is the time interval in hours since the last update that we are testing against to determine of the signatures are up-to-date
	maxUpdateTime := time.Duration(2)

	// Location of resulting JSON file to be written
	aemJSONFile := os.Getenv("ProgramData") + "/CentraStage/AEMAgent/antivirus.json"

	// Get values from the Registry to use
	product, installLocation, err := getValuesFromRegistry(eamGUID)

	filePath := installLocation + "/a2settings.ini"
	scanner, err := utfutil.NewScanner(filePath, utfutil.WINDOWS)
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	datestring, err := readDate(scanner)
	if err != nil {
		log.Fatal(err)
	}

	// parse dateString
	lastUpdate, err := strconv.Atoi(datestring)
	if err != nil {
		log.Fatal(err)
	}

	// checkDate
	upToDate := checkDate(lastUpdate, time.Hour*maxUpdateTime)

	//checkService
	serviceRunning := checkService("a2AntiMalware")

	result := aemJSON{
		Product:  product,
		Running:  serviceRunning,
		UpToDate: upToDate,
	}

	output, err := json.Marshal(result)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", output)
	err1 := ioutil.WriteFile(aemJSONFile, output, os.ModePerm)
	if err1 != nil {
		log.Fatal(err1)
	}

}
