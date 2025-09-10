package main

import (
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type CloakedName struct {
	target     string
	ipv4       []net.IP
	ipv6       []net.IP
	lastUpdate *time.Time
	lineNo     int
	isIP       bool
	PTR        []string
}

type PluginCloak struct {
	sync.RWMutex
	ttl            uint32
	createPTR      bool
	// Hot-reloading support
	configFile     string
	configWatcher  *ConfigWatcher
	stagingMatcher *PatternMatcher
}

type PluginCloakExtension struct {
	patternMatcher *PatternMatcher
	category       string
	detail         string
	blockingUrl    string
}

var cloakNamesDefault = PluginCloakExtension{nil, "default", "", ""}
var cloakNamesSafeSearch = PluginCloakExtension{nil, "safesearch", "", ""}
var cloakNamesCategoryPorn = PluginCloakExtension{nil, "porn", "", "blocked.tryohana.com"}
var cloakNamesCategoryHateFakescam = PluginCloakExtension{nil, "hatefakescam", "", "blocked.tryohana.com"}
var cloakNamesCategoryDrugs = PluginCloakExtension{nil, "drugs", "", "blocked.tryohana.com"}
var cloakNamesCategoryGambling = PluginCloakExtension{nil, "gambling", "", "blocked.tryohana.com"}
var cloakNamesCategoryPiracy = PluginCloakExtension{nil, "piracy", "", "blocked.tryohana.com"}
var cloakNamesCategoryTyposquatting = PluginCloakExtension{nil, "typosquatting", "", "blocked.tryohana.com"}
var cloakNamesCategoryDating = PluginCloakExtension{nil, "dating", "", "blocked.tryohana.com"}
var cloakNamesUserDefined = PluginCloakExtension{nil, "userDefined", "", "blocked.tryohana.com"}
var cloakNamesAppAssociated = PluginCloakExtension{nil, "appAssociated", "", "blocked.tryohana.com"}

var cloakNamesServiceBadService = PluginCloakExtension{nil, "service", "badservice", "blocked.tryohana.com"}
var cloakNamesServiceFacebook = PluginCloakExtension{nil, "service", "facebook", "blocked.tryohana.com"}
var cloakNamesServiceInstagram = PluginCloakExtension{nil, "service", "instagram", "blocked.tryohana.com"}
var cloakNamesServiceTikTok = PluginCloakExtension{nil, "service", "tiktok", "blocked.tryohana.com"}

var cloakNamesServiceSnapchat = PluginCloakExtension{nil, "service", "snapchat", "blocked.tryohana.com"}
var cloakNamesServiceTwitterX = PluginCloakExtension{nil, "service", "twitter", "blocked.tryohana.com"}
var cloakNamesServiceThreads = PluginCloakExtension{nil, "service", "threads", "blocked.tryohana.com"}
var cloakNamesServiceReddit = PluginCloakExtension{nil, "service", "reddit", "blocked.tryohana.com"}
var cloakNamesServicePinterest = PluginCloakExtension{nil, "service", "pinterest", "blocked.tryohana.com"}
var cloakNamesServiceTelegram = PluginCloakExtension{nil, "service", "telegram", "blocked.tryohana.com"}
var cloakNamesServiceBeReal = PluginCloakExtension{nil, "service", "bereal", "blocked.tryohana.com"}


var cloakNamesServiceYouTube = PluginCloakExtension{nil, "service", "youtube", "blocked.tryohana.com"}
var cloakNamesServiceVimeo = PluginCloakExtension{nil, "service", "vimeo", "blocked.tryohana.com"}
var cloakNamesServiceDailymotion = PluginCloakExtension{nil, "service", "dailymotion", "blocked.tryohana.com"}

var cloakNamesServiceNetflix = PluginCloakExtension{nil, "service", "netflix", "blocked.tryohana.com"}
var cloakNamesServiceTwitch = PluginCloakExtension{nil, "service", "twitch", "blocked.tryohana.com"}
var cloakNamesServiceDisneyPlus = PluginCloakExtension{nil, "service", "disneyplus", "blocked.tryohana.com"}
var cloakNamesServiceHulu = PluginCloakExtension{nil, "service", "hulu", "blocked.tryohana.com"}
var cloakNamesServiceAmazonPrime = PluginCloakExtension{nil, "service", "amazonprime", "blocked.tryohana.com"}
var cloakNamesServiceMax = PluginCloakExtension{nil, "service", "max", "blocked.tryohana.com"}
var cloakNamesServiceDazn = PluginCloakExtension{nil, "service", "dazn", "blocked.tryohana.com"}
var cloakNamesServiceWOW = PluginCloakExtension{nil, "service", "wow", "blocked.tryohana.com"}
var cloakNamesServiceJoyn = PluginCloakExtension{nil, "service", "joyn", "blocked.tryohana.com"}
var cloakNamesServiceRTLPlus = PluginCloakExtension{nil, "service", "rtlplus", "blocked.tryohana.com"}
var cloakNamesServiceCrunchyroll = PluginCloakExtension{nil, "service", "crunchyroll", "blocked.tryohana.com"}
var cloakNamesServiceParamount = PluginCloakExtension{nil, "service", "paramount", "blocked.tryohana.com"}
var cloakNamesServiceToggo = PluginCloakExtension{nil, "service", "toggo", "blocked.tryohana.com"}

var cloakNamesServiceOpenAI = PluginCloakExtension{nil, "service", "openai", "blocked.tryohana.com"}
var cloakNamesServiceGemini = PluginCloakExtension{nil, "service", "gemini", "blocked.tryohana.com"}
var cloakNamesServiceGrok = PluginCloakExtension{nil, "service", "grok", "blocked.tryohana.com"}
var cloakNamesServiceCopilot = PluginCloakExtension{nil, "service", "copilot", "blocked.tryohana.com"}
var cloakNamesServiceClaude = PluginCloakExtension{nil, "service", "claude", "blocked.tryohana.com"}
var cloakNamesServiceDeepSeek = PluginCloakExtension{nil, "service", "deepseek", "blocked.tryohana.com"}
var cloakNamesServiceMistral = PluginCloakExtension{nil, "service", "mistral", "blocked.tryohana.com"}
var cloakNamesServiceReplika = PluginCloakExtension{nil, "service", "replika", "blocked.tryohana.com"}
var cloakNamesServiceCharacterAI = PluginCloakExtension{nil, "service", "characterai", "blocked.tryohana.com"}



func (plugin *PluginCloak) Name() string {
	return "cloak"
}

func (plugin *PluginCloak) Description() string {
	return "Return a synthetic IP address or a flattened CNAME for specific names"
}

func (pluginExtension *PluginCloakExtension) initExtensions(proxy *Proxy, file string) error {
	dlog.Noticef("Loading the set of cloaking rules from [%s]", file)
	bin, err := ReadTextFile(file)
	if err != nil {
		return err
	}
	pluginExtension.patternMatcher = NewPatternMatcher()
	cloakedNames := make(map[string]*CloakedName)
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		var target string
		if pluginExtension.blockingUrl != "" { //SUPPORT PREDEFINED BLOCKING URLS AND PURE DOMAIN LISTS
			target = pluginExtension.blockingUrl
		} else {
			parts := strings.FieldsFunc(line, unicode.IsSpace)
			if len(parts) == 2 {
				line = strings.TrimSpace(parts[0])
				target = strings.TrimSpace(parts[1])
			} else if len(parts) > 2 {
				dlog.Errorf("Syntax error in cloaking rules at line %d -- Unexpected space character", 1+lineNo)
				continue
			}
			if len(line) == 0 || len(target) == 0 {
				dlog.Errorf("Syntax error in cloaking rules at line %d -- Missing name or target", 1+lineNo)
				continue
			}
		}

		line = strings.ToLower(line)
		cloakedName, found := cloakedNames[line]
		if !found {
			cloakedName = &CloakedName{}
		}
		ip := net.ParseIP(target);
		if ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				cloakedName.ipv4 = append((*cloakedName).ipv4, ipv4)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				cloakedName.ipv6 = append((*cloakedName).ipv6, ipv6)
			} else {
				dlog.Errorf("Invalid IP address in cloaking rule at line %d", 1+lineNo)
				continue
			}
			cloakedName.isIP = true
		} else {
			cloakedName.target = target
		}
		cloakedName.lineNo = lineNo + 1
		cloakedNames[line] = cloakedName

		if !proxy.cloakedPTR || strings.Contains(line, "*") || !cloakedName.isIP {
    			continue
    		}

    		var ptrLine string
    		if ipv4 := ip.To4(); ipv4 != nil {
    			reversed, _ := dns.ReverseAddr(ip.To4().String())
    			ptrLine = strings.TrimSuffix(reversed, ".")
    		} else {
    			reversed, _ := dns.ReverseAddr(cloakedName.ipv6[0].To16().String())
    			ptrLine = strings.TrimSuffix(reversed, ".")
    		}
    		ptrQueryLine := ptrEntryToQuery(ptrLine)
    		ptrCloakedName, found := cloakedNames[ptrQueryLine]
    		if !found {
    			ptrCloakedName = &CloakedName{}
    		}
    		ptrCloakedName.isIP = true
    		ptrCloakedName.PTR = append((*ptrCloakedName).PTR, ptrNameToFQDN(line))
    		ptrCloakedName.lineNo = lineNo + 1
    		cloakedNames[ptrQueryLine] = ptrCloakedName

	}
	for line, cloakedName := range cloakedNames {
		if err := pluginExtension.patternMatcher.Add(line, cloakedName, cloakedName.lineNo); err != nil {
			return err
		}
	}
	return nil
}

func (pluginExtension *PluginCloakExtension) initExtensionsMemory(proxy *Proxy) error {

	pluginExtension.patternMatcher = NewPatternMatcher()
	newCloakedName := &CloakedName{}
	newCloakedName.target = pluginExtension.blockingUrl
	newCloakedName.lineNo = 1
	//newCloakedName.isIP = false

	if err := pluginExtension.patternMatcher.Add("blocked", newCloakedName, newCloakedName.lineNo); err != nil {
		return err
	}

	return nil
}

func (plugin *PluginCloak) Init(proxy *Proxy) error {
	plugin.ttl = proxy.cloakTTL
	plugin.createPTR = proxy.cloakedPTR

	var error = cloakNamesDefault.initExtensions(proxy, proxy.cloakFile)

    if error == nil {
    	error = cloakNamesSafeSearch.initExtensions(proxy, proxy.cloakSafeSearchFile)
    }
    if error == nil {
    	error = cloakNamesCategoryPorn.initExtensions(proxy, proxy.cloakPornFile)
    }
    if error == nil {
    	error = cloakNamesCategoryDating.initExtensions(proxy, proxy.cloakDatingFile)
    }
    if error == nil {
    	error = cloakNamesCategoryHateFakescam.initExtensions(proxy, proxy.cloakHateFakeScamFile)
    }
    if error == nil {
    	error = cloakNamesCategoryDrugs.initExtensions(proxy, proxy.cloakDrugsFile)
    }
    if error == nil {
    	error = cloakNamesCategoryGambling.initExtensions(proxy, proxy.cloakGamblingFile)
    }
    if error == nil {
    	error = cloakNamesCategoryPiracy.initExtensions(proxy, proxy.cloakPiracyFile)
    }
    if error == nil {
    	error = cloakNamesCategoryTyposquatting.initExtensions(proxy, proxy.cloakTypoSquattingFile)
    }
    if error == nil {
    	error = cloakNamesServiceBadService.initExtensions(proxy, proxy.cloakBadServicesFile)
    }
    if error == nil {
    	error = cloakNamesServiceFacebook.initExtensions(proxy, proxy.cloakFacebookFile)
    }
    if error == nil {
    	error = cloakNamesServiceInstagram.initExtensions(proxy, proxy.cloakInstagramFile)
    }
    if error == nil {
    	error = cloakNamesServiceTikTok.initExtensions(proxy, proxy.cloakTikTokFile)
    }
    if error == nil {
    	error = cloakNamesServiceSnapchat.initExtensions(proxy, proxy.cloakSnapchatFile)
    }
    if error == nil {
    	error = cloakNamesServiceTwitterX.initExtensions(proxy, proxy.cloakTwitterXFile)
    }
    if error == nil {
    	error = cloakNamesServiceThreads.initExtensions(proxy, proxy.cloakThreadsFile)
    }
    if error == nil {
    	error = cloakNamesServiceReddit.initExtensions(proxy, proxy.cloakRedditFile)
    }
    if error == nil {
    	error = cloakNamesServicePinterest.initExtensions(proxy, proxy.cloakPinterestFile)
    }
    if error == nil {
    	error = cloakNamesServiceTelegram.initExtensions(proxy, proxy.cloakTelegramFile)
    }
    if error == nil {
    	error = cloakNamesServiceBeReal.initExtensions(proxy, proxy.cloakBeRealFile)
    }
    if error == nil {
    	error = cloakNamesServiceYouTube.initExtensions(proxy, proxy.cloakYouTubeFile)
    }
    if error == nil {
    	error = cloakNamesServiceVimeo.initExtensions(proxy, proxy.cloakVimeoFile)
    }
    if error == nil {
    	error = cloakNamesServiceDailymotion.initExtensions(proxy, proxy.cloakDailyMotionFile)
    }
    if error == nil {
    	error = cloakNamesServiceNetflix.initExtensions(proxy, proxy.cloakNetflixFile)
    }
    if error == nil {
    	error = cloakNamesServiceTwitch.initExtensions(proxy, proxy.cloakTwitchFile)
    }
    if error == nil {
    	error = cloakNamesServiceDisneyPlus.initExtensions(proxy, proxy.cloakDisneyPlusFile)
    }
    if error == nil {
    	error = cloakNamesServiceHulu.initExtensions(proxy, proxy.cloakHuluFile)
    }
    if error == nil {
    	error = cloakNamesServiceAmazonPrime.initExtensions(proxy, proxy.cloakAmazonPrimeFile)
    }
    if error == nil {
    	error = cloakNamesServiceMax.initExtensions(proxy, proxy.cloakMaxFile)
    }
    if error == nil {
    	error = cloakNamesServiceDazn.initExtensions(proxy, proxy.cloakDaznFile)
    }
    if error == nil {
    	error = cloakNamesServiceWOW.initExtensions(proxy, proxy.cloakWOWFile)
    }
    if error == nil {
    	error = cloakNamesServiceJoyn.initExtensions(proxy, proxy.cloakJoynFile)
    }
    if error == nil {
    	error = cloakNamesServiceRTLPlus.initExtensions(proxy, proxy.cloakRtlPlusFile)
    }
    if error == nil {
    	error = cloakNamesServiceCrunchyroll.initExtensions(proxy, proxy.cloakCrunchyrollFile)
    }
    if error == nil {
    	error = cloakNamesServiceParamount.initExtensions(proxy, proxy.cloakParamountFile)
    }
    if error == nil {
    	error = cloakNamesServiceToggo.initExtensions(proxy, proxy.cloakTogoFile)
    }
    if error == nil {
    	error = cloakNamesServiceOpenAI.initExtensions(proxy, proxy.cloakOpenAIFile)
    }
    if error == nil {
    	error = cloakNamesServiceGemini.initExtensions(proxy, proxy.cloakGeminiFile)
    }
    if error == nil {
    	error = cloakNamesServiceGrok.initExtensions(proxy, proxy.cloakGrokFile)
    }
    if error == nil {
    	error = cloakNamesServiceCopilot.initExtensions(proxy, proxy.cloakCoPilotFile)
    }
    if error == nil {
    	error = cloakNamesServiceClaude.initExtensions(proxy, proxy.cloakClaudeFile)
    }
    if error == nil {
    	error = cloakNamesServiceDeepSeek.initExtensions(proxy, proxy.cloakDeepSeekFile)
    }
    if error == nil {
    	error = cloakNamesServiceMistral.initExtensions(proxy, proxy.cloakMistralFile)
    }
    if error == nil {
    	error = cloakNamesServiceReplika.initExtensions(proxy, proxy.cloakReplikaFile)
    }
    if error == nil {
    	error = cloakNamesServiceCharacterAI.initExtensions(proxy, proxy.cloakCharacterAIFile)
    }
    if error == nil {
    	error = cloakNamesUserDefined.initExtensionsMemory(proxy)
    }
    if error == nil {
    	error = cloakNamesAppAssociated.initExtensionsMemory(proxy)
    }
    return error
}

func ptrEntryToQuery(ptrEntry string) string {
	return "=" + ptrEntry
}

func ptrNameToFQDN(ptrLine string) string {
	ptrLine = strings.TrimPrefix(ptrLine, "=")
	return ptrLine + "."
}

func (plugin *PluginCloak) Drop() error {
	return nil
}

// PrepareReload loads new cloaking rules into staging matcher but doesn't apply them yet
func (plugin *PluginCloak) PrepareReload() error {
	// Read the configuration file
	return nil
}

// ApplyReload atomically replaces the active pattern matcher with the staging one
func (plugin *PluginCloak) ApplyReload() error {
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginCloak) CancelReload() {
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginCloak) Reload() error {
    return nil
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginCloak) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (pluginExtension *PluginCloakExtension) eval(pluginsState *PluginsState, msg *dns.Msg, plugin *PluginCloak, block bool) error {
	question := msg.Question[0]

	if (question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeHTTPS && question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA && question.Qtype != dns.TypePTR)) && pluginsState.qName != "blocked" {
		return nil
	}

	now := time.Now()
	plugin.RLock()
	_, _, xcloakedName := pluginExtension.patternMatcher.Eval(pluginsState.qName)
	if xcloakedName == nil {
		plugin.RUnlock()
		return nil
	}

	//Dont start the Cloak operation but set the category in order to know that it matched

	if pluginsState.blockingInfo.UnblockingOverride {
		//not blocking
		plugin.RUnlock()
		pluginsState.blockingReason = pluginExtension.category
		return nil
	} else {
		//blocking code
		if block {
			cloakedName := xcloakedName.(*CloakedName)
			ttl, expired := plugin.ttl, false
			if cloakedName.lastUpdate != nil {
				if elapsed := uint32(now.Sub(*cloakedName.lastUpdate).Seconds()); elapsed < ttl {
					ttl -= elapsed
				} else {
					expired = true
				}
			}
			if !cloakedName.isIP && ((cloakedName.ipv4 == nil && cloakedName.ipv6 == nil) || expired) {
				target := cloakedName.target
				plugin.RUnlock()
				foundIPs, err := net.LookupIP(target)
				if err != nil {
					return nil
				}
				plugin.Lock()
				cloakedName.lastUpdate = &now
				cloakedName.ipv4 = nil
				cloakedName.ipv6 = nil
				for _, foundIP := range foundIPs {
					if ipv4 := foundIP.To4(); ipv4 != nil {
						cloakedName.ipv4 = append(cloakedName.ipv4, foundIP)
						if len(cloakedName.ipv4) >= 16 {
							break
						}
					} else {
						cloakedName.ipv6 = append(cloakedName.ipv6, foundIP)
						if len(cloakedName.ipv6) >= 16 {
							break
						}
					}
				}
				plugin.Unlock()
				plugin.RLock()
			}
			plugin.RUnlock()
			synth := EmptyResponseFromMessage(msg)
			synth.Answer = []dns.RR{}
			if question.Qtype == dns.TypeA {
				for _, ip := range cloakedName.ipv4 {
					rr := new(dns.A)
					rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
					rr.A = ip
					synth.Answer = append(synth.Answer, rr)
				}
			} else {
				if question.Qtype == dns.TypeHTTPS {
					rr := new(dns.HTTPS)
					rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassANY, Ttl: ttl}
					synth.Answer = append(synth.Answer, rr)
				} else if question.Qtype == dns.TypePTR {
                  		for _, ptr := range cloakedName.PTR {
                  			rr := new(dns.PTR)
                  			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
                  			rr.Ptr = ptr
                  			synth.Answer = append(synth.Answer, rr)
                  		}
                 } else {
					for _, ip := range cloakedName.ipv6 {
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
						rr.AAAA = ip
						synth.Answer = append(synth.Answer, rr)
					}
				}
			}
			rand.Shuffle(len(synth.Answer), func(i, j int) { synth.Answer[i], synth.Answer[j] = synth.Answer[j], synth.Answer[i] })
			pluginsState.synthResponse = synth
			pluginsState.action = PluginsActionSynth
			pluginsState.returnCode = PluginsReturnCodeCloak
			pluginsState.blockingReason = pluginExtension.category
			return nil
		} else {
			plugin.RUnlock()
			pluginsState.blockingReason = pluginExtension.category
			return nil
		}
	}
}

func containsIgnoreCase(slice []string, str string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, str) {
			return true
		}
	}
	return false
}

func (plugin *PluginCloak) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	if !pluginsState.blockingInfo.UnblockingOverride { //blocking path

		if pluginsState.sessionData["whitelisted"] != nil {
			return nil
		}

		//all unblocked sites are handled first
		if pluginsState.blockingInfo.AccessArray != nil {
			for _, accessListDomain := range pluginsState.blockingInfo.AccessArray {
				if strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(accessListDomain)) {
					return nil
				}
			}
		}

		if pluginsState.blockingInfo.AccessAliasArray != nil {
			for _, accessListDomain := range pluginsState.blockingInfo.AccessAliasArray {
				if strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(accessListDomain.Alias)) {
					return nil
				}
			}
		}

		if pluginsState.blockingInfo.AppAccessArray != nil {
			for _, accessListDomain := range pluginsState.blockingInfo.AccessArray {
				if strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(accessListDomain)) {
					return nil
				}
			}
		}

		if pluginsState.blockingInfo.AppDenyArray != nil {
			denyFound := false
			for _, denyistDomain := range pluginsState.blockingInfo.AppDenyArray {
				if !denyFound && strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(denyistDomain)) {
					denyFound = true
					dlog.Error(pluginsState.qName + " is part of deny list")
				}
			}

			if denyFound {
				var realDomain = pluginsState.qName
				pluginsState.qName = "blocked"
				var error = cloakNamesAppAssociated.eval(pluginsState, msg, plugin, true)
				if error != nil {
					dlog.Error(error)
				}
				pluginsState.qName = realDomain

				return error
			}
		}

		//all blocked sites are handled here
		if pluginsState.blockingInfo.DenyArray != nil {
			denyFound := false
			for _, denyistDomain := range pluginsState.blockingInfo.DenyArray {
				if !denyFound && strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(denyistDomain)) {
					denyFound = true
					dlog.Error(pluginsState.qName + " is part of deny list")
				}
			}

			if denyFound {
				var realDomain = pluginsState.qName
				pluginsState.qName = "blocked"
				var error = cloakNamesUserDefined.eval(pluginsState, msg, plugin, true)
				pluginsState.qName = realDomain
				if error != nil {
					dlog.Error(error)
				}
				return error
			}
		}

		if pluginsState.blockingInfo.DenyAliasArray != nil {
			denyFound := false
			var realDomain = pluginsState.qName //backup to set to access domain
			for _, denyistDomain := range pluginsState.blockingInfo.DenyAliasArray {
				if !denyFound && strings.Contains(strings.ToLower(pluginsState.qName), strings.ToLower(denyistDomain.Alias)) {
					realDomain = denyistDomain.Domain //set real domain for user
					denyFound = true
					dlog.Error(pluginsState.qName + " is part of deny alias list")
				}
			}

			if denyFound {
				pluginsState.qName = "blocked"
				var error = cloakNamesUserDefined.eval(pluginsState, msg, plugin, true)
				pluginsState.qName = realDomain
				if error == nil {
					dlog.Error(error)
				}
				return error
			}
		}

		//TODO CHECK STATE INFO -> return according state -> unblocking override is inside of eval below -> to tag domains by category

		dlog.Error("requesting: " + pluginsState.qName)

		//all database based blocking

		var error = cloakNamesDefault.eval(pluginsState, msg, plugin, true)

		if !pluginsState.blockingInfo.UnblockingOverride { //no safe search if override
			if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
				error = cloakNamesSafeSearch.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.SafeSearch)
			}
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryPorn.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Porn)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryDating.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Dating)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryHateFakescam.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.HateFakeScam)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryDrugs.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Drugs)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryGambling.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Gambling)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryPiracy.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Piracy)
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesCategoryTyposquatting.eval(pluginsState, msg, plugin, pluginsState.blockingInfo.Typosquatting)
		}

		//bad service -> always block
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceBadService.eval(pluginsState, msg, plugin, true)
		}

		//SOCIAL MEDIA
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceFacebook.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Facebook"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceInstagram.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Instagram"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceTikTok.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "TikTok"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceTwitterX.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "TwitterX"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceThreads.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Threads"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceReddit.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Reddit"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServicePinterest.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Pinterest"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceTelegram.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "Telegram"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceBeReal.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenySocialMediaServiceList, "BeReal"))
		}

		//VIDEO SERVICES
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceYouTube.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "YouTube"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceVimeo.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Vimeo"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceDailymotion.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "DailyMotion"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceNetflix.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Netflix"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceTwitch.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Twitch"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceDisneyPlus.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "DisneyPlus"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceHulu.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Hulu"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceAmazonPrime.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "AmazonPrime"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceMax.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Max"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceDazn.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Dazn"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceWOW.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "WOW"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceJoyn.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Joyn"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceRTLPlus.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "RTLPlus"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceCrunchyroll.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Crunchyroll"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceParamount.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Paramount"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceToggo.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyVideoServiceList, "Toggo"))
		}

		//AI Services
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceOpenAI.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "OpenAI"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceGemini.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "Gemini"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceGrok.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "Grok"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceClaude.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "Claude"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceDeepSeek.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "DeepSeek"))
		}
		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceMistral.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "Mistral"))
		}

		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceReplika.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "Replika"))
		}

		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceCharacterAI.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "CharacterAI"))
		}

		if error == nil && pluginsState.returnCode != PluginsReturnCodeCloak {
			error = cloakNamesServiceCopilot.eval(pluginsState, msg, plugin, containsIgnoreCase(pluginsState.blockingInfo.DenyAIServiceList, "CoPilot"))
		}

		//LOG ERROR
		if error != nil {
			dlog.Error(error)
		}
		return error
	} else {
		return nil
	}
}
