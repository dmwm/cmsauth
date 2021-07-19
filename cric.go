package cmsauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
)

// CricRecords defines type for CRIC records
type CricRecords map[string]CricEntry

// CricEntry represents structure in CRIC entry (used by CMS headers)
type CricEntry struct {
	DN    string              `json:"DN"`    // CRIC DN
	DNs   []string            `json:"DNs"`   // List of all DNs assigned to user
	ID    int64               `json:"ID"`    // CRIC ID
	Login string              `json:"LOGIN"` // CRIC Login name
	Name  string              `json:"NAME"`  // CRIC user name
	Roles map[string][]string `json:"ROLES"` // CRIC user roles
}

// String returns string representation of CricEntry
func (c *CricEntry) String() string {
	var roles string
	for _, r := range c.Roles {
		for _, v := range r {
			roles = fmt.Sprintf("%s\n%v", roles, v)
		}
	}
	r := fmt.Sprintf("ID: %d\nLogin: %s\nName: %s\nDN: %s\nDNs: %v\nRoles: %s", c.ID, c.Login, c.Name, c.DN, c.DNs, roles)
	return r
}

// GetCricData downloads CRIC data
func GetCricData(rurl string, verbose bool) (map[string]CricEntry, error) {
	cricRecords := make(map[string]CricEntry)
	var entries []CricEntry
	client := HttpClient()
	req, err := http.NewRequest("GET", rurl, nil)
	if err != nil {
		return cricRecords, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Unable to place client request, %v", req)
		return cricRecords, err
	}
	defer resp.Body.Close()
	if verbose {
		dump, err := httputil.DumpRequestOut(req, true)
		log.Printf("http request: headers %v, request %v, response %s, error %v", req.Header, req, string(dump), err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to read response, %v", resp)
		return cricRecords, err
	}
	err = json.Unmarshal(body, &entries)
	if err != nil {
		return cricRecords, err
	}
	if verbose {
		log.Printf("obtained %d records", len(entries))
	}
	// convert list of entries into a map
	for _, rec := range entries {
		recDNs := rec.DNs
		if r, ok := cricRecords[rec.Login]; ok {
			recDNs = r.DNs
			recDNs = append(recDNs, rec.DN)
			rec.DNs = recDNs
			if verbose {
				fmt.Printf("\nFound duplicate CRIC record\n%s\n%s\n", rec.String(), r.String())
			}
		} else {
			recDNs = append(recDNs, rec.DN)
			rec.DNs = recDNs
		}
		cricRecords[rec.Login] = rec
	}
	return cricRecords, nil
}

// ParseCric allows to parse CRIC file
func ParseCric(fname string, verbose bool) (map[string]CricEntry, error) {
	cricRecords := make(map[string]CricEntry)
	var entries []CricEntry
	if _, err := os.Stat(fname); err == nil {
		jsonFile, err := os.Open(fname)
		if err != nil {
			log.Println(err)
			return cricRecords, err
		}
		defer jsonFile.Close()
		byteValue, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			log.Println(err)
			return cricRecords, err
		}
		json.Unmarshal(byteValue, &entries)
		// convert list of entries into a map
		for _, rec := range entries {
			recDNs := rec.DNs
			if r, ok := cricRecords[rec.Login]; ok {
				recDNs = r.DNs
				recDNs = append(recDNs, rec.DN)
				rec.DNs = recDNs
				if verbose {
					fmt.Printf("\nFound duplicate CRIC record\n%s\n%s\n", rec.String(), r.String())
				}
			} else {
				recDNs = append(recDNs, rec.DN)
				rec.DNs = recDNs
			}
			cricRecords[rec.Login] = rec
		}
	}
	return cricRecords, nil
}
