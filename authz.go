package cmsauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"net/http"
	"os"
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
		hkey, err := os.ReadFile(afile)
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
func (a *CMSAuth) GetHmac(r *http.Request, verbose bool) (string, error) {
	var hkeys []string
	for h := range r.Header {
		key := strings.ToLower(h)
		if (strings.HasPrefix(key, "cms-authn") || strings.HasPrefix(key, "cms-authz")) && key != "cms-authn-hmac" {
			hkeys = append(hkeys, h)
		}
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
	if verbose {
		fmt.Println("key", string(a.hkey))
		fmt.Println("val", val)
	}
	return hmac, nil
}

// helper function to perform authorization action
func (a *CMSAuth) checkAuthorization(header http.Header) bool {
	return true
}

// CheckAuthnAuthz function performs Authentication and Authorization
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

// CheckCMSAuthz function performs CMS Authorization based on provided
// role and group or site attributes
func (a *CMSAuth) CheckCMSAuthz(header http.Header, role, group, site string) bool {
	for key, vals := range header {
		if strings.HasPrefix(strings.ToLower(key), "cms-authz") && strings.Contains(strings.ToLower(key), strings.ToLower(role)) {
			for _, val := range vals {
				v := strings.ToLower(val)
				if strings.Contains(v, strings.ToLower(group)) || strings.Contains(v, strings.ToLower(site)) {
					return true
				}
			}
		}
	}
	return false
}

// SetCMSHeaders sets HTTP headers for given http request based on on provider user and CRIC data
func (a *CMSAuth) SetCMSHeaders(r *http.Request, userData map[string]interface{}, cricRecords CricRecords, verbose bool) {
	// set cms auth headers
	r.Header.Set("cms-auth-status", "ok")
	r.Header.Set("cms-authn-name", iString(userData["name"]))
	login := iString(userData["cern_upn"])
	if rec, ok := cricRecords[login]; ok {
		// set DN
		r.Header.Set("cms-authn-dn", rec.DN)
		r.Header.Set("cms-auth-cert", rec.DN)
		// set group roles
		for k, v := range rec.Roles {
			key := fmt.Sprintf("cms-authz-%s", k)
			val := strings.Join(v, " ")
			r.Header.Set(key, val)
		}
	}
	r.Header.Set("cms-authn-login", login)
	r.Header.Set("cms-authn-method", "X509Cert")
	r.Header.Set("cms-cern-id", iString(userData["cern_person_id"]))
	r.Header.Set("cms-email", iString(userData["email"]))
	r.Header.Set("cms-auth-time", iString(userData["auth_time"]))
	r.Header.Set("cms-auth-expire", iString(userData["exp"]))
	r.Header.Set("cms-session", iString(userData["session_state"]))
	r.Header.Set("cms-request-uri", r.URL.Path)
	if hmac, err := a.GetHmac(r, verbose); err == nil {
		r.Header.Set("cms-authn-hmac", hmac)
	}
}

// SetCMSHeadersByKey sets HTTP headers for given http request based on on provider user and CRIC data
func (a *CMSAuth) SetCMSHeadersByKey(r *http.Request, userData map[string]interface{}, cricRecords CricRecords, key, method string, verbose bool) {
	// set cms auth headers
	r.Header.Set("cms-auth-status", "ok")
	r.Header.Set("cms-authn-name", iString(userData["name"]))
	if vvv, ok := userData[key]; ok {
		val := iString(vvv)
		if rec, ok := cricRecords[val]; ok {
			// set DN
			r.Header.Set("cms-authn-dn", rec.DN)
			r.Header.Set("cms-auth-cert", rec.DN)
			r.Header.Set("cms-authn-login", rec.Login)
			r.Header.Set("cms-cern-id", iString(rec.ID))
			// set group roles
			for k, v := range rec.Roles {
				key := fmt.Sprintf("cms-authz-%s", k)
				val := strings.Join(v, " ")
				r.Header.Set(key, val)
			}
		}
	}
	r.Header.Set("cms-authn-method", method)
	r.Header.Set("cms-email", iString(userData["email"]))
	r.Header.Set("cms-auth-time", iString(userData["auth_time"]))
	r.Header.Set("cms-auth-expire", iString(userData["exp"]))
	r.Header.Set("cms-session", iString(userData["session_state"]))
	r.Header.Set("cms-request-uri", r.URL.Path)
	if hmac, err := a.GetHmac(r, verbose); err == nil {
		r.Header.Set("cms-authn-hmac", hmac)
	}
}

// helper function to return string representation of interface value
func iString(v interface{}) string {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", t)
	case float32, float64:
		return fmt.Sprintf("%d", int64(t.(float64)))
	default:
		return fmt.Sprintf("%v", t)
	}
}
