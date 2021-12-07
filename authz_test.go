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
	group := "dbs"
	role := "operator"
	site := "T1"
	res := cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, false)

	header["cms-authz-operator"] = []string{"group:dbs"}
	res = cmsAuth.CheckCMSAuthz(header, role, group, site)
	assert.Equal(t, res, true)
}
