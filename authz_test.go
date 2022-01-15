package cmsauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCheckCMSAuthz function
func TestCheckCMSAuthz(t *testing.T) {
	var cmsAuth CMSAuth
	cmsAuth.Init("/etc/hosts")
	header := make(http.Header)
	group := "xcache"
	role := "operator"
	site := "T1"
	res := cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, false)

	header["Cms-Authz-Operator"] = []string{"group:dbs group:xcache"}
	header["Cms-Authz-Dbsexpert"] = []string{"group:dbs"}
	header["Cms-Authz-Developer"] = []string{"group:reqmgr2"}
	header["Cms-Authz-Admin"] = []string{"group:reqmgr group:das"}
	header["Cms-Authz-Users"] = []string{"group:users"}
	res = cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, true)

	header["cms-authz-operator"] = []string{"group:dbs group:xcache"}
	res = cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, true)

	site = ""
	res = cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, true)

	header = make(http.Header)
	header["Cms-Authz-Operator"] = []string{"group:dbs group:xcache"}
	res = cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, true)
}
