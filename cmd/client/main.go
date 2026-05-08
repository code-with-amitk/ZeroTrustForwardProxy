package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"zerotrust-forward-proxy/jwt"
	"zerotrust-forward-proxy/logging"
)

type scenario struct {
	name        string
	method      string
	user        string
	targetURL   string
	authHeader  string
	body        string
	expectCode  int
	expectInMsg string
}

// Create HTTP Client
func buildProxyClient(proxyAddr string, timeout time.Duration) (*http.Client, error) {

	// Parse server URL "http://127.0.0.1:8080"
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	// Create HTTP Client
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// runScenario executes one request through proxy and prints pass/fail.
func runScenario(client *http.Client, s scenario) error {

	// Create HTTP Request, set headers
	req, err := http.NewRequest(s.method, s.targetURL, bytes.NewBufferString(s.body))
	if err != nil {
		return err
	}

	// Bearer token("Bearer valid:alice") set from scenarios:authHeader in main()
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}
	if s.body != "" {
		req.Header.Set("Content-Type", "text/plain")
	}

	req.Header.Set("User-Agent", "ztfp-client/1.0")

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", dump)

	// Send HTTP Request and get response in resp
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	ok := resp.StatusCode == s.expectCode
	if s.expectInMsg != "" && !bytes.Contains(b, []byte(s.expectInMsg)) {
		ok = false
	}

	status := "FAIL"
	if ok {
		status = "PASS"
	}
	fmt.Printf("[%s] %s\n", status, s.name)
	fmt.Printf("  URL: %s\n", s.targetURL)
	fmt.Printf("  Got: %d\n", resp.StatusCode)
	fmt.Printf("  Expected: %d\n", s.expectCode)
	if len(body) > 180 {
		body = body[:180] + "..."
	}
	fmt.Printf("  Body: %q\n\n", body)
	return nil
}

func main() {

	// Create 2 variables
	// variable1= proxy. default value="http://127.0.0.1:8080"
	// variable2= timeout. default value=15 seconds
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "Proxy URL")
	timeout := flag.Duration("timeout", 15*time.Second, "Client timeout")
	flag.Parse()

	// Create HTTP Client using proxyAddr
	client, err := buildProxyClient(*proxyAddr, *timeout)
	if err != nil {
		fmt.Printf("client init error: %v\n", err)
		return
	}

	logger, err := logging.InitLogger()
	if err != nil {
		logger.Error(err)
	}
	jwtToken, err := jwt.GenerateJWT(logger, "alice", 1)
	if err != nil {
		logger.Error("generate JWT:", err)
	}

	scenarios := []scenario{
		{
			//GET is Fetch root webpage (index) of example.com.
			//GET / HTTP/1.1
			//Host: google.com
			//Headers:
			//	User-Agent: ztfp-client/1.0
			//	Authorization: Bearer XXXX (user=alice)
			//	Accept-Encoding: gzip
			name:       "HTTP allow by domain",
			method:     http.MethodGet,
			user:       "alice",
			targetURL:  "http://www.google.com/",
			authHeader: "Bearer " + jwtToken,
			expectCode: http.StatusOK,
		},
		{
			//GET / HTTP/1.1
			//Host: http://www.youtube.com/
			//Headers:
			//	User-Agent: ztfp-client/1.0
			//	Authorization: Bearer XXXX (user=alice)
			//	Accept-Encoding: gzip
			name:        "HTTP block by domain",
			method:      http.MethodGet,
			targetURL:   "http://www.youtube.com/", //policy.yaml= block youtube.com
			authHeader:  "Bearer " + jwtToken,
			expectCode:  http.StatusForbidden,
			expectInMsg: "policy blocked request",
		},
		{
			// POST is post data to REST Endpoint
			// POST http://example.com/REST-Endpoint1
			// Body:
			//	Contains card like number
			name:        "HTTP DLP request-body block",
			method:      http.MethodPost,
			targetURL:   "http://example.com/REST-Endpoint1",
			authHeader:  "Bearer " + jwtToken,
			body:        "my card is 4111 1111 1111 1111",
			expectCode:  http.StatusForbidden,
			expectInMsg: "dlp violation",
		},
		/*
			{
				//GET / HTTP/1.1
				//Host: example.com
				//User-Agent: ztfp-client/1.0
				//Authorization: Bearer valid:alice
				//Accept-Encoding: gzip
				name:       "HTTPS CONNECT allow path",
				method:     http.MethodGet,
				targetURL:  "https://example.com/",
				authHeader: "Bearer valid:alice",
				expectCode: http.StatusOK,
			},
			{
				//POST / HTTP/1.1
				//Host: example.com
				//User-Agent: ztfp-client/1.0
				//Content-Length: 29
				//Authorization: Bearer valid:alice
				//Content-Type: text/plain
				//Accept-Encoding: gzip
				name:        "HTTPS CONNECT + DLP block",
				method:      http.MethodPost,
				targetURL:   "https://example.com/",
				authHeader:  "Bearer valid:alice",
				body:        "api_key = SUPERSECRETKEY12345",
				expectCode:  http.StatusForbidden,
				expectInMsg: "dlp violation",
			},
			{
				//GET / HTTP/1.1
				//Host: a.internal.example.com
				//User-Agent: ztfp-client/1.0
				//Authorization: Bearer token-without-valid-prefix
				//Accept-Encoding: gzip
				name:        "HTTP policy block for anonymous user rule",
				method:      http.MethodGet,
				targetURL:   "http://a.internal.example.com/",
				authHeader:  "Bearer token-without-valid-prefix",
				expectCode:  http.StatusForbidden,
				expectInMsg: "policy blocked request",
			},
		*/
	}

	fmt.Printf("Running %d scenarios via proxy %s\n\n", len(scenarios), *proxyAddr)

	for _, s := range scenarios {
		if err := runScenario(client, s); err != nil {
			fmt.Printf("[ERROR] %s: %v\n\n", s.name, err)
		}
	}
}
