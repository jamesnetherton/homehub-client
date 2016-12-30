package homehub

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type hubResourceRequest struct {
	authData authData
	URL      string
	prev     request
}

func newHubResourceRequest(authData *authData, URL string, prev request) (req *hubResourceRequest) {
	return &hubResourceRequest{*authData, URL, prev}
}

func (r *hubResourceRequest) send() (re *response, err error) {

	resp, err := r.prev.send()
	if err != nil {
		return nil, err
	}

	logPath := resp.ResponseBody.Reply.ResponseActions[0].ResponseCallbacks[0].Parameters.URI
	sessionData := newSessionData(&r.authData)

	cj, _ := json.Marshal(sessionData)

	httpRequest, _ := http.NewRequest("GET", r.URL+"/"+logPath, nil)
	httpRequest.Header.Set("Accept", "application/json, text/plain, */*")
	httpRequest.Header.Set("Accept-Encoding", "gzip, deflate")
	httpRequest.Header.Set("Accept-Language", "en-GB,en-US;q=0.8,en;q=0.6")
	httpRequest.AddCookie(&http.Cookie{Name: "lang", Value: "en"})
	httpRequest.AddCookie(&http.Cookie{Name: "session", Value: url.QueryEscape(string(cj))})

	dump, _ := httputil.DumpRequest(httpRequest, true)
	log.Println(string(dump))

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}

	dump, _ = httputil.DumpResponse(httpResponse, true)
	log.Println(string(dump))

	defer httpResponse.Body.Close()
	response := &response{}
	bodyBytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	response.body = string(bodyBytes[:])

	return response, nil
}
