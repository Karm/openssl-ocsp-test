/*
Copyright (C) 2018  Michal Karm Babacek

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func runIt(t *testing.T, opensslPath string, cycles int, ocspPort string, additionalParams []string) {
	clientCert, revokedClientCert, caCert := loadCerts()
	for index := 0; index < cycles; index++ {
		ocspCMD := startOCSPResponder(ocspPort, opensslPath, additionalParams)
		// Waiting for TCP is not O.K., the server rejects client's subsequent reqeusts. Resulting to hardcoded sleep.
		time.Sleep(50 * time.Millisecond)
		revoked, responseOK := certIsRevokedOCSP(clientCert, caCert, "http://localhost:"+ocspPort)
		assert.True(t, responseOK, fmt.Sprintf("Iter: %d Response should have been valid.", index))
		assert.False(t, revoked, fmt.Sprintf("Iter: %d Cert is not supposed to be revoked.", index))
		revoked, responseOK = certIsRevokedOCSP(revokedClientCert, caCert, "http://localhost:"+ocspPort)
		assert.True(t, responseOK, fmt.Sprintf("Iter: %d Response should have been valid.", index))
		assert.True(t, revoked, fmt.Sprintf("Iter: %d Cert is supposed to be revoked.", index))
		stopOCSPResponder(ocspCMD)
	}
}

func TestOpenSSL111(t *testing.T) {
	runIt(t, "./openssl-static-binaries/openssl-1.1.1", 10, "2502", []string{
		"-nrequest",
		"1000",
		"-timeout",
		"5"})
}

func TestOpenSSL110i(t *testing.T) {
	runIt(t, "./openssl-static-binaries/openssl-1.1.0i", 10, "2503", []string{
		"-nrequest",
		"1000",
		"-timeout",
		"5"})
}

func TestOpenSSL102p(t *testing.T) {
	runIt(t, "./openssl-static-binaries/openssl-1.0.2p", 10, "2504", []string{
		"-nrequest",
		"1000",
		"-timeout",
		"5"})
}

func TestOpenSSL098zh(t *testing.T) {
	runIt(t, "./openssl-static-binaries/openssl-0.9.8zh", 10, "2505", []string{
		"-nrequest",
		"1000",
		"-timeout",
		"5"})
}
