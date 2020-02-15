package cmsauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
)

// StringList allows to sort string keys
type StringList []string

func (s StringList) Len() int           { return len(s) }
func (s StringList) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s StringList) Less(i, j int) bool { return s[i] < s[j] }

// CMSAuth is a generic type which holds auth. file and associated key
type CMSAuth struct {
	afile string
	hkey  []byte
}

// Init method initializes CMSAuth auth file, i.e. read the key
func (a *CMSAuth) Init(afile string) {
	a.afile = afile
	if len(afile) != 0 {
		hkey, err := ioutil.ReadFile(afile)
		if err != nil {
			msg := fmt.Sprintf("CMSAuth, unable to read %s, error %v", afile, err)
			fmt.Println(msg)
			return
		}
		a.hkey = hkey
	}
}

// helper function which checks Authentication
func (a *CMSAuth) checkAuthentication(headers http.Header) bool {
	var val interface{}
	val = headers["cms-auth-status"]
	if val == nil {
		return false
	}
	values := val.([]string)
	if len(values) == 1 && values[0] == "NONE" {
		// user authentication is optional
		return true
	}
	var hkeys []string
	for kkk := range headers {
		hkeys = append(hkeys, kkk)
	}
	sort.Sort(StringList(hkeys))
	var prefix, suffix, hmacValue string
	for _, kkk := range hkeys {
		values := headers[kkk]
		key := strings.ToLower(kkk)
		if (strings.HasPrefix(key, "cms-authn") || strings.HasPrefix(key, "cms-authz")) && key != "cms-authn-hmac" {
			prefix += fmt.Sprintf("h%xv%x", len(key), len(values[0]))
			suffix += fmt.Sprintf("%s%s", key, values[0])
			if strings.HasPrefix(key, "cms-authn") {
				headers[strings.Replace(key, "cms-authn-", "", 1)] = values
			}
		}
		if key == "cms-authn-hmac" {
			hmacValue = values[0]
		}
	}
	value := []byte(fmt.Sprintf("%s#%s", prefix, suffix))
	var sha1hex hash.Hash
	if len(a.afile) != 0 {
		sha1hex = hmac.New(sha1.New, a.hkey)
	} else {
		sha1hex = sha1.New()
	}
	sha1hex.Write(value)
	hmacFound := fmt.Sprintf("%x", sha1hex.Sum(nil))
	if hmacFound != hmacValue {
		return false
	}
	return true
}

// GetHmac calculates hmac value from request headers
func (a *CMSAuth) GetHmac(r *http.Request) (string, error) {
	var hkeys []string
	for h, _ := range r.Header {
		hkeys = append(hkeys, h)
	}
	var prefix, suffix string
	sort.Sort(StringList(hkeys))
	for _, h := range hkeys {
		v := r.Header.Get(h)
		prefix = fmt.Sprintf("%sh%xv%x", prefix, len(h), len(v))
		suffix = fmt.Sprintf("%s%s%s", suffix, strings.ToLower(h), v)
	}
	val := fmt.Sprintf("%s#%s", prefix, suffix)
	var sha1hex hash.Hash
	sha1hex = hmac.New(sha1.New, a.hkey)
	sha1hex.Write([]byte(val))
	hmac := fmt.Sprintf("%x", sha1hex.Sum(nil))
	return hmac, nil
}

// helper function to perform authorization action
func (a *CMSAuth) checkAuthorization(header http.Header) bool {
	return true
}

// CheckAuthnAuthz function perfoms Authentication and Authorization
func (a *CMSAuth) CheckAuthnAuthz(header http.Header) bool {
	if a.afile == "" { // no auth file is provided
		return true
	}
	status := a.checkAuthentication(header)
	if !status {
		return status
	}
	return a.checkAuthorization(header)
}
