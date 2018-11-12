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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ocsp"
)

const (
	bindHost              = "localhost"
	caCertFile            = "certs/ca/certs/ca-chain.cert.pem"
	clientCertFile        = "certs/client/certs/client-777.cert.pem"
	revokedClientCertFile = "certs/client/certs/client-888.cert.pem"
	ocspCert              = "certs/ocsp/certs/ocsp.cert.pem"
	ocspKey               = "certs/ocsp/private/ocsp.key.nopass.pem"
	index                 = "certs/ca/intermediate-index.txt"
	// This is also used by openssl: certs/ca/intermediate-index.txt.attr
)

var (
	ocspOpts = ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}
	ocspRead = ioutil.ReadAll
)

func certIsRevokedOCSP(leaf *x509.Certificate, caCert *x509.Certificate, ocspURL string) (revoked, ok bool) {
	ocspRequest, err := ocsp.CreateRequest(leaf, caCert, &ocspOpts)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	resp, err := sendOCSPRequest(ocspURL, ocspRequest, leaf, caCert)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	ok = true
	if resp.Status != ocsp.Good {
		revoked = true
	}
	return
}

func sendOCSPRequest(server string, req []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp *http.Response
	var err error
	buf := bytes.NewBuffer(req)
	resp, err = http.Post(server, "application/ocsp-request", buf)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve OSCP resonse")
	}
	body, err := ocspRead(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ocsp.ParseResponseForCert(body, leaf, issuer)
}

func stopOCSPResponder(ocspCMD *exec.Cmd) {
	if ocspCMD != nil && ocspCMD.Process != nil {
		ocspCMD.Process.Signal(syscall.SIGINT)
		//ocspCMD.Process.Kill()
		//time.Sleep(1 * time.Second)
		//if ocspCMD.Process != nil {
		//	ps := exec.Command("kill", "-HUP", fmt.Sprintf("%d", ocspCMD.Process.Pid))
		//	ps.Wait()
		//}
	}
}

func startOCSPResponder(ocspURL string, opensslPath string, additionalParams []string) *exec.Cmd {
	cmd := []string{
		"ocsp",
		"-port",
		ocspURL,
		"-index",
		index,
		"-CA",
		caCertFile,
		"-rkey",
		ocspKey,
		"-rsigner",
		ocspCert,
	}
	ocspCMD := exec.Command(opensslPath, append(cmd, additionalParams...)...)
	go func(o *exec.Cmd) {
		out, _ := o.CombinedOutput()
		log.Println(string(out))
	}(ocspCMD)
	return ocspCMD
}

func loadCerts() (clientCert *x509.Certificate, revokedClientCert *x509.Certificate, caCert *x509.Certificate) {
	caCertBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, caCertBytes := pem.Decode(caCertBytes)
	if block == nil {
		log.Fatal("Could not load caCert")
	}
	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clientCertBytes, err := ioutil.ReadFile(clientCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, clientCertBytes = pem.Decode(clientCertBytes)
	if block == nil {
		log.Fatal("Could not load clientCert")
	}
	clientCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	revokedClientCertBytes, err := ioutil.ReadFile(revokedClientCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, revokedClientCertBytes = pem.Decode(revokedClientCertBytes)
	if block == nil {
		log.Fatal("Could not load clientCert")
	}
	revokedClientCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return clientCert, revokedClientCert, caCert
}

func main() {
	log.Println("Silence.")
}
