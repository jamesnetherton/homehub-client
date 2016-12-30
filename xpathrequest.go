package homehub

type xpathRequest struct {
	genericRequest
}

func newXPathRequest(authData *authData, xpath string) (req *xpathRequest) {
	authData.requestCount++

	method := "getValue"
	if xpath == "Device" {
		method = "reboot"
	}

	capabilityFlags := &capabilityFlags{
		Interface: true,
	}

	interfaceOptions := &interfaceOptions{
		CapabilityFlags: *capabilityFlags,
	}

	a := action{
		ID:               0,
		Method:           method,
		XPath:            xpath,
		InterfaceOptions: interfaceOptions,
	}

	var actions []action
	actions = append(actions, a)
	requestBody := newRequestBody(authData, actions)

	return &xpathRequest{
		genericRequest: genericRequest{
			*requestBody,
			*authData,
		},
	}
}
