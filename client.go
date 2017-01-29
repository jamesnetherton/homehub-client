package homehub

type client struct {
	authData authData
}

func newClient(URL string, username string, password string) *client {
	a := authData{
		url:      URL,
		userName: username,
		password: password,
	}
	return &client{a}
}

func (c *client) doReboot() (err error) {
	req := newRebootRequest(&c.authData)
	_, err = req.send()
	return err
}

func (c *client) getBandwidthUsage() (result string, err error) {
	bandwidthMonitorRequest := newBandwidthMonitorRequest(&c.authData)
	req := newHubResourceRequest(&c.authData, c.authData.url, bandwidthMonitorRequest)
	resp, err := req.send()
	if err != nil {
		return "", err
	}

	return resp.body, nil
}

func (c *client) getEventLog() (result string, err error) {
	eventLogRequest := newEventLogRequest(&c.authData)
	req := newHubResourceRequest(&c.authData, c.authData.url, eventLogRequest)
	resp, err := req.send()

	if err != nil {
		return "", err
	}

	return resp.body, nil
}

func (c *client) getXPathValue(xpath string) (result string, err error) {
	req := newXPathRequest(&c.authData, xpath, methodGetValue, nil)
	resp, err := req.send()

	if err == nil {
		return resp.getValue(), nil
	}

	return "", err
}

func (c *client) getXPathValues(xpath string) (values [][]value, err error) {
	req := newXPathRequest(&c.authData, xpath, methodGetValue, nil)
	resp, err := req.send()

	if err == nil {
		return resp.getValues(xpath), nil
	}

	return nil, err
}

func (c *client) getXPathHostValue(xpath string) (h *host, err error) {
	req := newXPathRequest(&c.authData, xpath, methodGetValue, nil)
	resp, err := req.send()

	if err == nil {
		return resp.getHost(), nil
	}

	return nil, err
}

func (c *client) setXPathValue(xpath string, value interface{}) (err error) {
	req := newXPathRequest(&c.authData, xpath, methodSetValue, value)
	_, err = req.send()
	return err
}
