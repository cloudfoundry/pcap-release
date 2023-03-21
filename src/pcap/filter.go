package pcap

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// interfaceAddrs provides a list of all known network addresses.
var interfaceAddrs = net.InterfaceAddrs

// containsForbiddenRunes checks whether a given string contains
// any character that is less than 32 or more than 126.
//
// See: https://www.lookuptables.com/text/ascii-table
func containsForbiddenRunes(in string) bool {
	for _, r := range in {
		if r < 32 || r > 126 {
			return true
		}
	}
	return false
}

// patchFilter extends the given filter by excluding the filter generated
// by generateApiFilter.
func patchFilter(filter string) (string, error) {
	apiFilter, err := generateAPIFilter()
	if err != nil {
		return "", err
	}

	filter = strings.TrimSpace(filter)

	if filter == "" {
		return fmt.Sprintf("not (%s)", apiFilter), nil
	}

	return fmt.Sprintf("not (%s) and (%s)", apiFilter, filter), nil
}

// generateApiFilter takes all IP addresses as returned by interfaceAddrs and
// generates a filter for those IP addresses (loopback is excluded from the filter).
// Note: the filter *matches* all of those IP addresses.
func generateAPIFilter() (string, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("unable to get IPs: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("unable to determine ip addresses")
	}

	var ipFilters []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		// check that:
		// * ipNet is actually an IP address
		// * it is not a loopback address
		// * can be represented in either 4- or 16-bytes representation
		if ok && !ipNet.IP.IsLoopback() {
			// Check whether the IP is v4 or v6. If both evaluate to true
			// v4 takes precedence.
			var expression string
			switch {
			case ipNet.IP.To4() != nil:
				expression = "ip"
			case ipNet.IP.To16() != nil:
				expression = "ip6"
			default:
				return "", fmt.Errorf("address %s is not IPv4 or v6", ipNet.IP.String())
			}

			ipFilters = append(ipFilters, fmt.Sprintf("%s host %s", expression, ipNet.IP.String()))
		}
	}
	return strings.Join(ipFilters, " or "), nil
}

// validateDevice is a go implementation of dev_valid_name from the linux kernel.
//
// See: https://lxr.linux.no/linux+v6.0.9/net/core/dev.c#L995
func validateDevice(name string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("validate device: %w", err)
		}
	}()

	if len(name) > maxDeviceNameLength {
		return fmt.Errorf("name too long: %d > %d", len(name), maxDeviceNameLength)
	}

	if name == "." || name == ".." {
		return fmt.Errorf("invalid name: '%s'", name)
	}

	for i, r := range name {
		if r == '/' {
			return fmt.Errorf("%w at pos. %d: '/'", errIllegalCharacter, i)
		}
		if r == '\x00' {
			return fmt.Errorf("%w at pos. %d: '\\0'", errIllegalCharacter, i)
		}
		if r == ':' {
			return fmt.Errorf("%w at pos. %d: ':'", errIllegalCharacter, i)
		}
		if unicode.Is(unicode.White_Space, r) {
			return fmt.Errorf("%w: whitespace at pos %d", errIllegalCharacter, i)
		}
	}

	return nil
}
