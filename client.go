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

func (c *client) sendXPathRequest(xpath string) (result string, err error) {
	req := newXPathRequest(&c.authData, xpath)
	resp, err := req.send()

	if err == nil {
		return resp.getValue(), nil
	}

	return "", err
}
