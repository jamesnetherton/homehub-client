package homehub

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type apiTest struct {
	method          string
	methodArgs      []interface{}
	apiStubResponse string
	expectedResult  interface{}
	t               *testing.T
}

func getEnv(name string, defaultValue string) string {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}
	return value
}

func santizeString(target *string, regex string, replacement string) {
	re := regexp.MustCompile(regex)
	for _, match := range re.FindAllString(*target, -1) {
		*target = strings.Replace(*target, match, replacement, -1)
	}
}

func newHubClient(URL string, username string, password string) *HubClient {
	c := newClient(URL+"/cgi/json-req", username, password)
	return &HubClient{c, URL, &firmwareSG4B1{}}
}

func stubbedResponseHTTPHandler(apiStubResponse string, w http.ResponseWriter, r *http.Request) {
	var stubDataFile string
	if strings.HasSuffix(r.RequestURI, "/eventLog") {
		stubDataFile = "testdata/eventLog.txt"
	} else if strings.HasSuffix(r.RequestURI, "/stats.csv") {
		stubDataFile = "testdata/stats.csv"
	} else {
		stubDataFile = "testdata/" + apiStubResponse + "_response.json"
	}

	bytesRead, err := ioutil.ReadFile(stubDataFile)
	if err == nil {
		fmt.Fprintln(w, string(bytesRead))
	} else {
		fmt.Fprintln(w, "{\"reply\": { \"uid\": 0 \"id\": 0 \"error\": \"code\": 99999999, \"description\": \""+err.Error()+"\" }}")
	}
}

func proxiedResponseHTTPHandler(apiStubResponse string, url string, w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest(r.Method, url+r.RequestURI, r.Body)
	req.ContentLength = r.ContentLength
	req.Form = r.Form
	req.Header = r.Header

	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintln(w, "{\"reply\": { \"uid\": 0 \"id\": 0 \"error\": { \"code\": 99999999, \"description\": \""+err.Error()+"\" }}}")
		return
	}

	defer httpResponse.Body.Close()
	bodyBytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		fmt.Fprintln(w, "{\"reply\": { \"uid\": 0 \"id\": 0 \"error\": { \"code\": 99999999, \"description\": \"Error reading proxied response\" }}}")
		return
	}

	body := string(bodyBytes[:])

	// Clean up MAC addresses
	santizeString(&body, "\\b([0-9a-fA-F]{2}:??){5}([0-9a-fA-F]{2})\\b", "11:AA:2B:33:44:5C")
	// Clean up IP addresses
	santizeString(&body, "\\b((25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})\\b", "192.168.1.68")
	// Clean up timestampts
	santizeString(&body, "\\b([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\\+([0-9]{4})\\b", "2016-08-30T19:48:55+0100")
	// Clean up serial number
	santizeString(&body, "\\b([0-9]{6})\\+([A-Z]{2})([0-9]{8})\\b", "123456+NQ98765432")

	var dat map[string]interface{}
	err = json.Unmarshal([]byte(body), &dat)
	if err != nil {
		fmt.Fprintln(w, "{\"reply\": { \"uid\": 0 \"id\": 0 \"error\": { \"code\": 99999999, \"description\": \"Error unmarshalling JSON response\" }}}")
		return
	}

	json, err := json.MarshalIndent(dat, "", "  ")
	if err != nil {
		fmt.Fprintln(w, "{\"reply\": { \"uid\": 0 \"id\": 0 \"error\": { \"code\": 99999999, \"description\": \"Error marshalling JSON response\" }}}")
		return
	}

	ioutil.WriteFile("testdata/"+apiStubResponse+"_response.json", json, 0644)
	fmt.Fprintln(w, body)
}

func mockAPIClientServer(apiStubResponse ...string) (*httptest.Server, Hub) {
	defaultUsername := "admin"
	defaultPassword := "passw0rd"
	username := getEnv("HUB_USERNAME", defaultUsername)
	password := getEnv("HUB_PASSWORD", defaultPassword)
	debug := getEnv("HUB_DEBUG", "false")
	requestCount := -1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/cgi/json-req" {
			requestCount++
		}

		if username == defaultUsername && password == defaultPassword {
			stubbedResponseHTTPHandler(apiStubResponse[requestCount], w, r)
		} else {
			proxiedResponseHTTPHandler(apiStubResponse[requestCount], os.Getenv("HUB_URL"), w, r)
		}
	}))

	url := getEnv("HUB_URL", server.URL)
	hub := newHubClient(server.URL, username, password)

	if debug == "true" {
		hub.EnableDebug(true)
	}

	if url != server.URL {
		hub.Login()
	} else {
		hub.client.authData.userName = "admin"
		hub.client.authData.password = "admin"
		hub.client.authData.sessionID = "987879"
		hub.client.authData.nonce = "2355345"
	}

	return server, hub
}

func testAPIResponse(a *apiTest) {
	server, hub := mockAPIClientServer(a.apiStubResponse)
	defer server.Close()

	v := reflect.TypeOf(hub)

	apiMethod, _ := v.MethodByName(a.method)

	inputs := make([]reflect.Value, len(a.methodArgs)+1)
	for i := range a.methodArgs {
		inputs[i+1] = reflect.ValueOf(a.methodArgs[i])
	}

	inputs[0] = reflect.ValueOf(hub)
	resp := apiMethod.Func.Call(inputs)
	var result interface{}

	if resp[0].Type().String() == "string" {
		result = resp[0].String()
	} else if resp[0].Type().String() == "int" {
		result = int(resp[0].Int())
	} else if resp[0].Type().String() == "int64" {
		result = int64(resp[0].Int())
	} else if resp[0].Type().String() == "bool" {
		result = resp[0].Bool()
	} else if resp[0].Type().String() == "error" {
		if !resp[0].IsNil() {
			a.t.Fatalf("API method %s returned an unexpected error", a.method)
		}
	}

	if len(resp) > 1 {
		if !resp[1].IsNil() {
			if resp[1].Type().String() == "error" {
				result = fmt.Sprintf("%s", resp[1].Interface())
			}
		}
	}

	if result != a.expectedResult {
		a.t.Fatalf("API method %v returned '%v'. Expected '%v'", a.method, result, a.expectedResult)
	}
}

func TestBandwidthMonitor(t *testing.T) {
	server, hub := mockAPIClientServer("bandwidth_monitor")
	defer server.Close()

	res, err := hub.BandwidthMonitor()

	assert.Nil(t, err)
	assert.Len(t, res.Entries, 2)
	assert.Equal(t, "a0:b1:c2:d3:e4:f5", res.Entries[0].MACAddress)
	assert.Equal(t, "2016-12-30", res.Entries[0].Date)
	assert.Equal(t, 10959, res.Entries[0].DownloadMegabytes)
	assert.Equal(t, 1301, res.Entries[0].UploadMegabytes)
	assert.Equal(t, "a1:b9:c8:d7:e6:f5", res.Entries[1].MACAddress)
	assert.Equal(t, "2016-12-31", res.Entries[1].Date)
	assert.Equal(t, 218, res.Entries[1].DownloadMegabytes)
	assert.Equal(t, 30, res.Entries[1].UploadMegabytes)
}

func TestBroadbandProductType(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "BroadbandProductType",
		apiStubResponse: "interface_type",
		expectedResult:  "BT Infinity",
		t:               t,
	})
}

func TestConnectedDevices(t *testing.T) {
	server, hub := mockAPIClientServer("connected_devices")
	defer server.Close()

	res, err := hub.ConnectedDevices()

	assert.Nil(t, err)
	assert.Len(t, res, 2)
	assert.Equal(t, "foo.bar", res[0].HostName)
	assert.Len(t, res[0].IPv4Addresses, 1)
	assert.Len(t, res[0].IPv6Addresses, 0)
}

func TestDataPumpVersion(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DataPumpVersion",
		apiStubResponse: "data_pump_version",
		expectedResult:  "AfH042f.d26k1\n",
		t:               t,
	})
}

func TestDataReceived(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DataReceived",
		apiStubResponse: "data_received",
		expectedResult:  int64(99887766),
		t:               t,
	})
}

func TestDataSent(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DataSent",
		apiStubResponse: "data_sent",
		expectedResult:  int64(11223344),
		t:               t,
	})
}

func TestDeviceInfo(t *testing.T) {
	server, hub := mockAPIClientServer("device_info")
	defer server.Close()

	res, err := hub.DeviceInfo(2)

	assert.Nil(t, err)
	assert.Equal(t, "foo.bar", res.HostName)
	assert.Len(t, res.IPv4Addresses, 1)
	assert.Len(t, res.IPv6Addresses, 0)
}

func TestDhcpAuthoritative(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DhcpAuthoritative",
		apiStubResponse: "dhcp_authoritative",
		expectedResult:  true,
		t:               t,
	})
}

func TestDhcpPoolStart(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DhcpPoolStart",
		apiStubResponse: "dhcp_ipv4_pool_start",
		expectedResult:  "192.168.1.68",
		t:               t})
}

func TestDhcpPoolEnd(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DhcpPoolEnd",
		apiStubResponse: "dhcp_ipv4_pool_end",
		expectedResult:  "192.168.1.253",
		t:               t,
	})
}

func TestDhcpSubnetMask(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DhcpSubnetMask",
		apiStubResponse: "dhcp_subnet_mask",
		expectedResult:  "255.255.255.0",
		t:               t,
	})
}

func TestDownstreamSyncSpeed(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "DownstreamSyncSpeed",
		apiStubResponse: "downstream_curr_rate",
		expectedResult:  97543,
		t:               t,
	})
}

func TestDownstreamSyncSpeedSg4b1a(t *testing.T) {
	server, hub := mockAPIClientServer("login", "maintenance_firmware_version_sg4b1a", "downstream_curr_rate_sg4b1a")
	defer server.Close()

	loggedIn, err := hub.Login()

	assert.Nil(t, err)
	assert.True(t, loggedIn)

	downstreamRate, err := hub.DownstreamSyncSpeed()

	assert.Nil(t, err)
	assert.Equal(t, 317796, downstreamRate)
}

func TestEventLog(t *testing.T) {
	server, hub := mockAPIClientServer("event_log")
	defer server.Close()

	res, err := hub.EventLog()

	assert.Nil(t, err)
	assert.Len(t, res.Entries, 2)
	assert.Equal(t, "01.03.2017 01:11:11", res.Entries[0].Timestamp)
	assert.Equal(t, "INF", res.Entries[0].Type)
	assert.Equal(t, "WIFI", res.Entries[0].Category)
	assert.Equal(t, "Test log message 1", res.Entries[0].Message)
	assert.Equal(t, "02.03.2017 02:22:22", res.Entries[1].Timestamp)
	assert.Equal(t, "WRN", res.Entries[1].Type)
	assert.Equal(t, "TR69", res.Entries[1].Category)
	assert.Equal(t, "ppp1:TR69 ConnectionRequest: processing request from ACS", res.Entries[1].Message)
}

func TestHardwareVersion(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "HardwareVersion",
		apiStubResponse: "hardware_version",
		expectedResult:  "1.0",
		t:               t,
	})
}

func TestInternetConnectionStatus(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "InternetConnectionStatus",
		apiStubResponse: "wan_internet_status",
		expectedResult:  "UP",
		t:               t,
	})
}

func TestLightBrightness(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "LightBrightness",
		apiStubResponse: "hub_light_brightness",
		expectedResult:  50,
		t:               t,
	})
}

func TestLightBrightnessSet(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "LightBrightnessSet",
		methodArgs:      []interface{}{50},
		apiStubResponse: "hub_light_brightness_set",
		expectedResult:  nil,
		t:               t,
	})
}

func TestLightEnable(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "LightEnable",
		methodArgs:      []interface{}{true},
		apiStubResponse: "hub_light_enable",
		expectedResult:  nil,
		t:               t,
	})
}

func TestLightStatus(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "LightStatus",
		apiStubResponse: "hub_light_status",
		expectedResult:  "OFF",
		t:               t,
	})
}

func TestLoginSuccess(t *testing.T) {
	server, hub := mockAPIClientServer("login", "maintenance_firmware_version")
	defer server.Close()

	loggedIn, err := hub.Login()

	assert.Nil(t, err)
	assert.True(t, loggedIn)
}

func TestLocalTime(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "LocalTime",
		apiStubResponse: "ntp_local_time",
		expectedResult:  "2016-08-30T19:48:55+0100",
		t:               t,
	})
}

func TestMaintenanceFirmwareVersion(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "MaintenanceFirmwareVersion",
		apiStubResponse: "maintenance_firmware_version",
		expectedResult:  "SG0B000000AA",
		t:               t,
	})
}

func TestNatRules(t *testing.T) {
	server, hub := mockAPIClientServer("nat_rules")
	defer server.Close()

	res, err := hub.NatRules()

	assert.Nil(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "awesome-nat-rule-alias", res[0].Alias)
	assert.False(t, res[0].AllExternalInterfaces)
	assert.Equal(t, "HUB_TESTER", res[0].Creator)
	assert.Equal(t, "Test NAT Rule description", res[0].Description)
	assert.True(t, res[0].Enable)
	assert.Equal(t, 1111, res[0].ExternalPort)
	assert.Equal(t, 0, res[0].ExternalPortEndRange)
	assert.Equal(t, "192.168.1.68", res[0].InternalClient)
	assert.Equal(t, 2222, res[0].InternalPort)
	assert.Equal(t, 60, res[0].LeaseDuration)
	assert.Equal(t, "2016-08-30T19:48:55+0100", res[0].LeaseStart)
	assert.Equal(t, "TCP", res[0].Protocol)
	assert.Equal(t, "192.168.1.68", res[0].RemoteHost)
	assert.Equal(t, "TEST_SERVICE", res[0].Service)
	assert.Equal(t, "ACCEPT", res[0].Target)
	assert.Equal(t, 1, res[0].UID)
}

func TestNatRule(t *testing.T) {
	server, hub := mockAPIClientServer("nat_rule")
	defer server.Close()

	natRule, err := hub.NatRule(1)

	assert.Nil(t, err)
	assert.Equal(t, "awesome-nat-rule-alias", natRule.Alias)
	assert.False(t, natRule.AllExternalInterfaces)
	assert.Equal(t, "HUB_TESTER", natRule.Creator)
	assert.Equal(t, "Test NAT Rule description", natRule.Description)
	assert.True(t, natRule.Enable)
	assert.Equal(t, 1111, natRule.ExternalPort)
	assert.Equal(t, 0, natRule.ExternalPortEndRange)
	assert.Equal(t, "192.168.1.68", natRule.InternalClient)
	assert.Equal(t, 2222, natRule.InternalPort)
	assert.Equal(t, 60, natRule.LeaseDuration)
	assert.Equal(t, "2016-08-30T19:48:55+0100", natRule.LeaseStart)
	assert.Equal(t, "TCP", natRule.Protocol)
	assert.Equal(t, "192.168.1.68", natRule.RemoteHost)
	assert.Equal(t, "TEST_SERVICE", natRule.Service)
	assert.Equal(t, "ACCEPT", natRule.Target)
	assert.Equal(t, 1, natRule.UID)
}

func TestNatRuleCreate(t *testing.T) {
	server, hub := mockAPIClientServer("nat_rule_create")
	defer server.Close()

	natRule := &NatRule{
		Enable:                false,
		Alias:                 "",
		ExternalInterface:     "",
		AllExternalInterfaces: false,
		LeaseDuration:         0,
		RemoteHost:            "",
		ExternalPort:          1111,
		ExternalPortEndRange:  1111,
		InternalInterface:     "",
		InternalPort:          0,
		Protocol:              "TCP",
		Service:               "Test Service",
		InternalClient:        "",
		Description:           "Test Description",
		Creator:               "JAMES",
		Target:                "REJECT",
		LeaseStart:            "",
	}

	err := hub.NatRuleCreate(natRule)

	assert.Nil(t, err)
	assert.Equal(t, 14, natRule.UID)
}

func TestNatRuleDelete(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "NatRuleDelete",
		methodArgs:      []interface{}{16},
		apiStubResponse: "nat_rule_delete",
		expectedResult:  nil,
		t:               t,
	})
}

func TestNatRuleUpdate(t *testing.T) {
	natRule := NatRule{
		UID:                   18,
		Enable:                true,
		Alias:                 "Updated Alias",
		ExternalInterface:     "",
		AllExternalInterfaces: false,
		LeaseDuration:         30,
		RemoteHost:            "",
		ExternalPort:          2222,
		ExternalPortEndRange:  2222,
		InternalInterface:     "",
		InternalPort:          0,
		Protocol:              "UDP",
		Service:               "FTP",
		InternalClient:        "",
		Description:           "Updated Test Description",
		Creator:               "HIDDEN",
		Target:                "DROP",
		LeaseStart:            "",
	}

	testAPIResponse(&apiTest{
		method:          "NatRuleUpdate",
		methodArgs:      []interface{}{natRule},
		apiStubResponse: "nat_rule_update",
		expectedResult:  nil,
		t:               t,
	})
}

func TestPublicIPAddress(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "PublicIPAddress",
		apiStubResponse: "public_ip4",
		expectedResult:  "192.168.1.68",
		t:               t,
	})
}

func TestPublicSubnetMask(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "PublicSubnetMask",
		apiStubResponse: "public_subnet_mask",
		expectedResult:  "255.255.255.255",
		t:               t,
	})
}

func TestReboot(t *testing.T) {
	// If we're testing against the real router, we don't want to reboot it midway through the test suite!
	if os.Getenv("HUB_USERNAME") == "" && os.Getenv("HUB_PASSWORD") == "" {
		testAPIResponse(&apiTest{
			method:          "Reboot",
			apiStubResponse: "reboot",
			expectedResult:  nil,
			t:               t,
		})
	}
}

func TestSambaHost(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "SambaHost",
		apiStubResponse: "samba_host",
		expectedResult:  "bthub,hub,bthomehub,api",
		t:               t,
	})
}

func TestSambaIP(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "SambaIP",
		apiStubResponse: "samba_ip",
		expectedResult:  "192.168.1.68",
		t:               t,
	})
}

func TestSerialNumber(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "SerialNumber",
		apiStubResponse: "serial_number",
		expectedResult:  "+123456+NQ98765432",
		t:               t,
	})
}

func TestSessionExpired(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "SerialNumber",
		apiStubResponse: "session_expired",
		expectedResult:  "Invalid user session",
		t:               t,
	})
}

func TestSoftwareVersion(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "SoftwareVersion",
		apiStubResponse: "software_version",
		expectedResult:  "SG4B10002244",
		t:               t,
	})
}

func TestUpstreamSyncSpeed(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "UpstreamSyncSpeed",
		apiStubResponse: "upstream_curr_rate",
		expectedResult:  52121,
		t:               t,
	})
}

func TestUpstreamSyncSpeedSg4b1a(t *testing.T) {
	server, hub := mockAPIClientServer("login", "maintenance_firmware_version_sg4b1a", "upstream_curr_rate_sg4b1a")
	defer server.Close()

	loggedIn, err := hub.Login()

	assert.Nil(t, err)
	assert.True(t, loggedIn)

	upstreamRate, err := hub.UpstreamSyncSpeed()

	assert.Nil(t, err)
	assert.Equal(t, 52121, upstreamRate)
}

func TestVersion(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "Version",
		apiStubResponse: "hub_version",
		expectedResult:  "Home Hub 60 Type A",
		t:               t,
	})
}

func TestWiFiFrequency24Ghz(t *testing.T) {
	server, hub := mockAPIClientServer("wifi_frequency24")
	defer server.Close()

	frequency, err := hub.WiFiFrequency24Ghz()

	assert.Nil(t, err)
	assert.Equal(t, "RADIO2G4", frequency.Alias)
	assert.Equal(t, "1,2,3,4,5", frequency.AvailableChannels)
	assert.Equal(t, 1, frequency.Channel)
	assert.True(t, frequency.Enable)
	assert.Equal(t, "b,g,n", frequency.OperatingStandards)
	assert.Equal(t, "UP", frequency.Status)
	assert.Equal(t, 1, frequency.UID)
}

func TestWiFiFrequency24GhzChannelSet(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "WiFiFrequency24GhzChannelSet",
		methodArgs:      []interface{}{6},
		apiStubResponse: "wifi_frequency24_channel_set",
		expectedResult:  nil,
		t:               t,
	})
}

func TestWiFiFrequency5Ghz(t *testing.T) {
	server, hub := mockAPIClientServer("wifi_frequency5")
	defer server.Close()

	frequency, err := hub.WiFiFrequency5Ghz()

	assert.Nil(t, err)
	assert.Equal(t, "RADIO5G", frequency.Alias)
	assert.Equal(t, "1,2,3,4,5", frequency.AvailableChannels)
	assert.Equal(t, 1, frequency.Channel)
	assert.True(t, frequency.Enable)
	assert.Equal(t, "a,n,ac", frequency.OperatingStandards)
	assert.Equal(t, "a,n,ac", frequency.SupportedStandards)
	assert.Equal(t, "UP", frequency.Status)
	assert.Equal(t, 1, frequency.UID)
}

func TestWiFiFrequency5GhzChannelSet(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "WiFiFrequency5GhzChannelSet",
		methodArgs:      []interface{}{36},
		apiStubResponse: "wifi_frequency5_channel_set",
		expectedResult:  nil,
		t:               t,
	})
}

func TestWiFiSecurityMode(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "WiFiSecurityMode",
		apiStubResponse: "wifi24_security_mode",
		expectedResult:  "ULTRA_SECURE_MODE",
		t:               t,
	})
}

func TestWiFiSSID(t *testing.T) {
	testAPIResponse(&apiTest{
		method:          "WiFiSSID",
		apiStubResponse: "wifi24_ssid",
		expectedResult:  "Click here for viruses",
		t:               t,
	})
}
