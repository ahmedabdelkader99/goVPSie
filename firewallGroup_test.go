package goEldelta

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

func TestFirewallGroupServiceHandlerDelete(t *testing.T) {
	client := NewClient(oauth2.NewClient(context.Background(), nil))

	client.SetUserAgent(userAgent)
	client.SetRequestHeaders(map[string]string{
		"Vpsie-Auth": "sampleToken",
	})

	err := client.FirewallGroup.Delete(context.Background(), "7dbcea52-f695-11ee-8bba-0050569c68dc")

	if err != nil {
		t.Error(err)
	}

}
