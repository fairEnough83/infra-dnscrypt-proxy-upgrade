package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"github.com/newrelic/go-agent/v3/newrelic"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type localDoHHandler struct {
	proxy *Proxy
}


//echo 'AAABAAABAAAAAAABCnA1Ny1jYWxkYXYGaWNsb3VkA2NvbQAAQQABAAApAgAAAAAAAE4ADABKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | base64 --decode | curl -i --http2 -k -H 'content-type: application/dns-message' -H 'X-Forwared-User-Id: 0UVPskesDDfFyrLBG9U65vd61Zz1' -H 'X-Forwared-Device-Id: 5574f2f3-6a21-41c5-a8a3-ee0ab669206e' -H 'X-Forwared-Brand: ohana' --data-binary @- http://localhost:9090/dns-query -o -

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy := handler.proxy

	if !proxy.clientsCountInc() {
		dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
		return
	}


	defer proxy.clientsCountDec()
	dataType := "application/dns-message"
	writer.Header().Set("Server", "dnscrypt-proxy")

	if request.URL.Path != proxy.localDoHPath && request.URL.Path != "/clear_cache"  && request.URL.Path != "/get_ip" && request.URL.Path != "/health" {
		dlog.Error("wrong url")
		writer.WriteHeader(404)
		return
	}

    if request.URL.Path == "/get_ip" {
    	// We'll always grab the first IP address in the X-Forwarded-For header
    	// list.  We do this because this is always the *origin* IP address, which
    	// is the *true* IP of the user.  For more information on this, see the
    	// Wikipedia page: https://en.wikipedia.org/wiki/X-Forwarded-For
    	err := request.ParseForm()
    	if err != nil {
    		panic(err)
    	}

        var ip = net.ParseIP(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0])
    	if ip == nil {
    		dlog.Error("IP from X-Forwarded-For was nil")
    		ip = net.ParseIP(strings.Split(request.RemoteAddr, ":")[0])
    	}


    	writer.Header().Set("Content-Type", "text/plain")
    	writer.WriteHeader(200)
    	writer.Write([]byte(ip.String()))
    	return
    }
	packet := []byte{}
	start := time.Now()
	clientAddr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
    if err != nil {
    	dlog.Errorf("Unable to get the client address: [%v]", err)
    	return
    }
    xClientAddr := net.Addr(clientAddr)

    if request.URL.Path == "/health" {
    	//use dummy data
    	packet, _ = base64.StdEncoding.DecodeString("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB") //www.example.com
    	response := proxy.processIncomingQuery("local_doh", proxy.mainProto, packet, &xClientAddr, nil, start, false, "default", "default", "", "ohana")
    	if len(response) == 0 {
    	    dlog.Error("health check failed")
    		writer.WriteHeader(500)

    	} else {
    		dlog.Error("health check succeeded")
    		writer.Header().Set("Content-Type", "text/plain")
    		writer.WriteHeader(200)
    		writer.Write([]byte("HEALTHY"))
    	}
        return
    }

    if request.Header.Get("Content-Type") != dataType { //TBD
    	dlog.Error("Content-Type is wrong: " + request.Header.Get("Content-Type"))
    	writer.Header().Set("Content-Type", "text/plain")
    	writer.WriteHeader(400)
    	writer.Write([]byte("dnscrypt-proxy local DoH server\n"))
    	return
    }

    userID := request.Header.Get("X-Forwared-User-Id")

    if userID == "" {
    		writer.Header().Set("Content-Type", "text/plain")
    		writer.WriteHeader(400)
    		writer.Write([]byte("no user included\n"))
    		dlog.Error("no user id included")
    		return
    	}

    	if request.URL.Path == "/clear_cache" {
    		apiKey := request.Header.Get("X-Forwared-API-KEY")
    		if apiKey == proxy.apiKey {
    			proxy.clearCache(userID)
    			dlog.Error("clear cache was successful for user: " + userID)
    		}
    		writer.Header().Set("Content-Type", dataType)
    		writer.WriteHeader(204)
    		return
    	}

    	deviceID := request.Header.Get("X-Forwared-Device-Id")

    	if deviceID == "" {
    		writer.Header().Set("Content-Type", "text/plain")
    		writer.WriteHeader(400)
    		writer.Write([]byte("no device included\n"))
    		dlog.Error("no device included")
    		return
    	}

    	currentMode := request.Header.Get("X-Forwared-Mode")

    	if currentMode == "" {
    		dlog.Error("no currentMode is included for user: " + userID)
    	}

    	brand := request.Header.Get("X-Forwared-Brand")

    	if brand == "" {
    		//use ohana fallback
    		brand = "ohana"
    	}

	if request.Method == "GET" {
		keys := request.URL.Query()["dns"]
		packet, _ = base64.StdEncoding.DecodeString(keys[0])
		if keys == nil {
			dlog.Error("No body in a local DoH query")
			return
		}
	} else {
		packet, err = ioutil.ReadAll(io.LimitReader(request.Body, MaxHTTPBodyLength))
		if err != nil {
			dlog.Error("No body in a local DoH query")
			return
		}
	}

	if len(packet) < MinDNSPacketSize {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(400)
		writer.Write([]byte("dnscrypt-proxy local DoH server\n"))
		return
	}

	hasEDNS0Padding, err := hasEDNS0Padding(packet)
	if err != nil {
		dlog.Error("hasEDNS0Padding failed")
		writer.WriteHeader(400)
		return
	}

	response := proxy.processIncomingQuery("local_doh", proxy.mainProto, packet, &xClientAddr, nil, start, false, userID, deviceID, currentMode, brand)
	if len(response) == 0 {
		dlog.Error("processIncomingQuery failed")
		writer.WriteHeader(500)
		return
	}

	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		dlog.Error("Unpack failed")
		writer.WriteHeader(500)
		return
	}

	responseLen := len(response)
	paddedLen := dohPaddedLen(responseLen)
	padLen := paddedLen - responseLen

	if hasEDNS0Padding {
		response, err = addEDNS0PaddingIfNoneFound(&msg, response, padLen)
		if err != nil {
			dlog.Critical(err)
			return
		}
	} else {
		pad := strings.Repeat("X", padLen)
		writer.Header().Set("X-Pad", pad)
	}

	writer.Header().Set("Content-Type", dataType)
	writer.Header().Set("Content-Length", fmt.Sprint(len(response)))
	writer.WriteHeader(200)
	writer.Write(response)
	dlog.Error("Process incoming request finished, send response sent")
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	app, _ := newrelic.NewApplication(
		newrelic.ConfigAppName("infra-dnscrypt-proxy"),
		newrelic.ConfigLicense("eu01xx1fef5482e22b57eacf74a9911c6c60NRAL"),
		func(config *newrelic.Config) {
			config.CustomInsightsEvents.Enabled = false
			config.DistributedTracer.Enabled = false
			config.TransactionEvents.Enabled = false
			config.ErrorCollector.Enabled = true
			config.CrossApplicationTracer.Enabled = false
			config.BrowserMonitoring.Enabled = false
			config.Attributes.Enabled = false
			config.SpanEvents.Enabled = false
			config.ServerlessMode.Enabled = false
			config.RuntimeSampler.Enabled = true
			config.DatastoreTracer.DatabaseNameReporting.Enabled = false
			config.DatastoreTracer.InstanceReporting.Enabled = false
			config.DatastoreTracer.QueryParameters.Enabled = false
			config.DatastoreTracer.SlowQuery.Enabled = false
		},
	)

	if len(proxy.localDoHCertFile) == 0 || len(proxy.localDoHCertKeyFile) == 0 {
		dlog.Fatal("A certificate and a key are required to start a local DoH service")
	}

	_, handler := newrelic.WrapHandle(app, proxy.localDoHPath, localDoHHandler{proxy: proxy})

	h2cHandler := h2c.NewHandler(handler, &http2.Server{})

	httpServer := &http.Server{
		ReadTimeout:  proxy.timeout,
		WriteTimeout: proxy.timeout,
		Handler:      h2cHandler,
	}

	httpServer.SetKeepAlivesEnabled(true)

	//NGINX DOES SSL TERMINATION
	if err := httpServer.Serve(acceptPc); err != nil {
		dlog.Fatal(err)
	}

	/**if err := httpServer.ServeTLS(acceptPc, proxy.localDoHCertFile, proxy.localDoHCertKeyFile); err != nil {
		dlog.Fatal(err)
	}**/
}

func dohPaddedLen(unpaddedLen int) int {
	boundaries := [...]int{64, 128, 192, 256, 320, 384, 512, 704, 768, 896, 960, 1024, 1088, 1152, 2688, 4080, MaxDNSPacketSize}
	for _, boundary := range boundaries {
		if boundary >= unpaddedLen {
			return boundary
		}
	}
	return unpaddedLen
}
