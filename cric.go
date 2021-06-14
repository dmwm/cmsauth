package cmsauth

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
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

// GetCricDataByKey downloads CRIC data
func GetCricDataByKey(rurl, key string, verbose bool) (map[string]CricEntry, error) {
	cricRecords := make(map[string]CricEntry)
	entries, err := GetCricEntries(rurl, verbose)
	if err != nil {
		return cricRecords, err
	}
	// convert list of entries into a map
	for _, rec := range entries {
		var k string
		if strings.ToLower(key) == "login" {
			k = rec.Login
		} else if strings.ToLower(key) == "id" {
			k = fmt.Sprintf("%d", rec.ID)
		} else if strings.ToLower(key) == "name" {
			k = rec.Name
		} else if strings.ToLower(key) == "dn" {
			k = rec.DN
		} else {
			msg := fmt.Sprintf("provided key=%s is not supported", key)
			return cricRecords, errors.New(msg)
		}
		recDNs := rec.DNs
		if r, ok := cricRecords[k]; ok {
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
		cricRecords[k] = rec
	}
	return cricRecords, nil
}

// GetCricData downloads CRIC data
func GetCricData(rurl string, verbose bool) (map[string]CricEntry, error) {
	cricRecords := make(map[string]CricEntry)
	entries, err := GetCricEntries(rurl, verbose)
	if err != nil {
		return cricRecords, err
	}
	// convert list of entries into a map
	for _, rec := range entries {
		recDNs := rec.DNs
		if r, ok := cricRecords[rec.DN]; ok {
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
		cricRecords[rec.DN] = rec
	}
	return cricRecords, nil
}

// GetCricEntries downloads CRIC data
func GetCricEntries(rurl string, verbose bool) ([]CricEntry, error) {
	var entries []CricEntry
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	req, err := http.NewRequest("GET", rurl, nil)
	if err != nil {
		return entries, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Unable to place client request, %v", req)
		return entries, err
	}
	defer resp.Body.Close()
	if verbose {
		dump, err := httputil.DumpRequestOut(req, true)
		log.Printf("http request: headers %v, request %v, response %s, error %v", req.Header, req, string(dump), err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to read response, %v", resp)
		return entries, err
	}
	err = json.Unmarshal(body, &entries)
	if err != nil {
		return entries, err
	}
	if verbose {
		log.Printf("obtained %d records", len(entries))
	}
	return entries, nil
}

// ParseCric allows to parse CRIC file and use cric Login as a key for cric entry map
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

// ParseCricByKey allows to parse CRIC file use use provided key as a cric entry map
func ParseCricByKey(fname, key string, verbose bool) (map[string]CricEntry, error) {
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
		// convert list of entries into a map based on provided key
		for _, rec := range entries {
			var k string
			if strings.ToLower(key) == "login" {
				k = rec.Login
			} else if strings.ToLower(key) == "id" {
				k = fmt.Sprintf("%d", rec.ID)
			} else if strings.ToLower(key) == "name" {
				k = rec.Name
			} else if strings.ToLower(key) == "dn" {
				k = rec.DN
			} else {
				msg := fmt.Sprintf("provided key=%s is not supported", key)
				return cricRecords, errors.New(msg)
			}
			recDNs := rec.DNs
			if r, ok := cricRecords[k]; ok {
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
			cricRecords[k] = rec
		}
	}
	return cricRecords, nil
}
