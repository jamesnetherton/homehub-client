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

func (c *client) getXPathValue(xpath string) (result string, err error) {
	req := newXPathRequest(&c.authData, xpath, methodGetValue, nil)
	resp, err := req.send()

	if err == nil {
		return resp.getValue(), nil
	}

	return "", err
}

func (c *client) setXPathValue(xpath string, value interface{}) (err error) {
	req := newXPathRequest(&c.authData, xpath, methodSetValue, value)
	_, err = req.send()
	return err
}
