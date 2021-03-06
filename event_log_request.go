package homehub

type eventLogRequest struct {
	genericRequest
}

func newEventLogRequest(authData *authData, xpath string) (req *eventLogRequest) {
	authData.requestCount++

	params := &parameters{
		FileName: "eventLog",
	}

	a := action{
		ID:         0,
		Method:     methodVendorLogDownload,
		XPath:      xpath,
		Parameters: params,
	}

	var actions []action
	actions = append(actions, a)
	requestBody := newRequestBody(authData, actions)

	return &eventLogRequest{
		genericRequest: genericRequest{
			*requestBody,
			*authData,
		},
	}
}
