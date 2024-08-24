package cmsauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetSortedDN function
func TestGetSortedDN(t *testing.T) {
	dn := "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=user/CN=123/CN=First Last"
	expect := "/CN=123/CN=First Last/CN=user/DC=cern/DC=ch/OU=Organic Units/OU=Users"
	sortedDN := GetSortedDN(dn)
	assert.Equal(t, sortedDN, expect)
}
