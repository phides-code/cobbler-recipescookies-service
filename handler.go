package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	expires := time.Now().Add(expiresInDuration)
	cookies, err := cfSigner.Sign(resourcePath, expires)
	if err != nil {
		errString := "Signing error: " + err.Error()
		log.Println(errString)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: errString}, nil
	}

	// Build response with Set-Cookie headers
	multiHeaders := map[string][]string{}
	for _, c := range cookies {
		multiHeaders["Set-Cookie"] = append(multiHeaders["Set-Cookie"],
			c.Name+"="+c.Value+"; Path=/; HttpOnly; Secure; SameSite=None")
	}

	return events.APIGatewayProxyResponse{
		StatusCode:        200,
		MultiValueHeaders: multiHeaders,
		Body:              "Signed cookies issued.",
		IsBase64Encoded:   false,
	}, nil
}
