package integration_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // this is the common way to import ginkgo and gomega
	. "github.com/onsi/gomega"    //nolint:revive // this is the common way to import ginkgo and gomega
)

func TestIntegrationTests(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "IntegrationTests Suite")
}
