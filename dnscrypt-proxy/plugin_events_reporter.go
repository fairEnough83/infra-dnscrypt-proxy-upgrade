package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	ttlcache "github.com/ReneKroon/ttlcache/v2"
	jwt "github.com/golang-jwt/jwt"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var debounceCache ttlcache.Cache

type PluginEventReporter struct {
	ignoredQtypes        []string
	cloakConfigJWTSecret string
	baseURL              string
}

func (plugin *PluginEventReporter) Name() string {
	return "event_reporter"
}

func (plugin *PluginEventReporter) Description() string {
	return "Reports Events."
}

func (plugin *PluginEventReporter) Init(proxy *Proxy) error {
	plugin.ignoredQtypes = proxy.queryLogIgnoredQtypes
	plugin.cloakConfigJWTSecret = proxy.cloakConfigJWTSecret
	plugin.baseURL = proxy.cloakConfigBaseUrl

	cache := ttlcache.NewCache()
	cache.SetTTL(time.Duration(120 * time.Second))
	cache.SkipTTLExtensionOnHit(true)
	cache.SetCacheSizeLimit(4000)
	debounceCache = *cache
	return nil
}

func (plugin *PluginEventReporter) Drop() error {
	return nil
}

func (plugin *PluginEventReporter) Reload() error {
	return nil
}

func (plugin *PluginEventReporter) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	var category = pluginsState.blockingReason
	var webFilterConfiguration = pluginsState.blockingInfo

	
	if pluginsState.deviceId == "default" {
		return nil
	}

	if !pluginsState.blockingInfo.UnblockingOverride { //unblocking override reports every time
		//check if category is deactivated
		if !webFilterConfiguration.Drugs && category == "drugs" {
			dlog.Error("Skip drugs: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		} 
		
		if !webFilterConfiguration.Dating && category == "dating" {
			dlog.Error("Skip dating: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		}

		if !webFilterConfiguration.Gambling && category == "gambling" {
			dlog.Error("Skip gambling: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		}

		if !webFilterConfiguration.HateFakeScam && category == "hatefakescam" {
			dlog.Error("Skip hatefakescam: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		}
		
		if !webFilterConfiguration.Porn && category == "porn" {
			dlog.Error("Skip porn: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			
			return nil
		}

		if !webFilterConfiguration.Piracy && category == "piracy" {
			dlog.Error("Skip piracy: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		}

		if !webFilterConfiguration.Typosquatting && category == "typosquatting" {
			dlog.Error("Skip typosquatting: " +  pluginsState.qName + " deviceId: " + pluginsState.deviceId)
			return nil
		}
	}

	if pluginsState.blockingReason != "" && pluginsState.blockingReason != "safesearch" && pluginsState.blockingReason != "service" {
		go plugin.postEvent(pluginsState.clientId, pluginsState.deviceId, pluginsState.qName, pluginsState.blockingReason, pluginsState.blockingInfo, pluginsState.brand)
	}
	return nil
}

func (plugin *PluginEventReporter) postEvent(clientID string, deviceID string, qname string, category string, webFilterConfiguration Webfilterconfigurations, brand string) error {

	if category != "appAssociated" {
		
		var domain, _ = publicsuffix.Domain(qname)

		dlog.Error("Try to postEvent: " + domain + " deviceId: " + deviceID + " brand: " + brand)
		
		_, debounce := debounceCache.Get(deviceID + "-" + domain)

		if debounce != nil {

			debounceCache.Set(deviceID + "-" + domain, "exists")

			var url = plugin.baseURL + "/api/events"
			v, missed := debounceCache.Get("access_token")
			var accessToken string

			if missed != nil {
				token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
					"sub":  "infra-dnscrypt-proxy",
					"auth": "ROLE_ADMIN",
					"exp":  time.Now().Add(time.Hour * 1).Unix(),
				})
				// Sign and get the complete encoded token as a string using the secret
				keyDec, _ := b64.StdEncoding.DecodeString(plugin.cloakConfigJWTSecret)
				newToken, _ := token.SignedString(keyDec)
				accessToken = newToken
				debounceCache.SetWithTTL("access_token", accessToken, time.Duration(10*time.Minute))
			} else {
				accessToken = v.(string)
			}

			var eventCategory string
			
			if webFilterConfiguration.UnblockingOverride {
				eventCategory = "SawExplicitContent"
			} else {
				eventCategory = "ExplicitContent"
			}

			var data = fmt.Sprintf("[{\"key\": \"domain\", \"value\": \"%s\"}, "+
				"{\"key\": \"contentCategory\", \"value\": \"%s\"}]", domain, category)

			body := &Events{
				Type:               "Violation",
				Category:           eventCategory,
				Source:             "infra-dnscrypt-proxy",
				Data:               data,
				Date:               time.Now().UTC().Format(time.RFC3339),
				User:               User{clientID},
				ConfirmationNeeded: false,
				CreatorUser:        User{"infra-dnscrypt-proxy"},
				Subject:            "WebFilterConfigurations",
				SubjectID:          fmt.Sprint(webFilterConfiguration.ID),
				ManagedDevice:      ManagedDevice{deviceID},
			}

			payloadBuf := new(bytes.Buffer)
			json.NewEncoder(payloadBuf).Encode(body)
			req, _ := http.NewRequest("POST", url, payloadBuf)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Firebase-AppCheck", "68a125ea-576d-44ac-8577-a1c5dbae90de")
			req.Header.Set("X-Ohana-Firebase-Instance-ID", "e61fb3c0-3edc-4758-8a93-b0f212bb0e0b")
			req.Header.Set("X-Ohana-Brand", brand)
			client := &http.Client{}
			res, e := client.Do(req)
			if e != nil {
				dlog.Error(e)
				return nil
			}
			defer res.Body.Close()
		} else {
			dlog.Error("Skip event reporting for: " + domain + " deviceId: " + deviceID)
		}
	}
	return nil
}

// var requestDuration time.Duration
// if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
// 	requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
// }
// var line string
// if plugin.format == "tsv" {
// 	now := time.Now()
// 	year, month, day := now.Date()
// 	hour, minute, second := now.Clock()
// 	tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
// 	line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%dms\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), qType, returnCode, requestDuration/time.Millisecond,
// 		StringQuote(pluginsState.serverName), StringQuote(pluginsState.clientId), StringQuote(pluginsState.blockingReason))
// } else if plugin.format == "ltsv" {
// 	cached := 0
// 	if pluginsState.cacheHit {
// 		cached = 1
// 	}
// 	line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\treturn:%s\tcached:%d\tduration:%d\tserver:%s\tuserId:%s\tblockingReason:%s\n",
// 		time.Now().Unix(), clientIPStr, StringQuote(qName), qType, returnCode, cached, requestDuration/time.Millisecond, StringQuote(pluginsState.serverName), StringQuote(pluginsState.clientId), StringQuote(pluginsState.blockingReason))
// } else {
// 	dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
// }
//return nil
