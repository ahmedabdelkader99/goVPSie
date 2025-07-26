package goVPSie

import (
	"context"
	"fmt"
	"net/http"
)

var firewallBasePath = "/apps/v2/firewall"

type FirewallService interface {
	ListMacros(ctx context.Context, options *ListOptions) ([]Macros, error)
	RemoveGroupVm(ctx context.Context, vmId, groupId string) error
}

type firewallServiceHandler struct {
	client *Client
}

var _ FirewallService = &firewallServiceHandler{}

type Macros struct {
	Descr string `json:"descr"`
	Macro string `json:"macro"`
}

type ListMacrosRoot []Macros

func (f *firewallServiceHandler) ListMacros(ctx context.Context, options *ListOptions) ([]Macros, error) {
	path := fmt.Sprintf("%s/macros", firewallBasePath)

	req, err := f.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var macros ListMacrosRoot
	if err = f.client.Do(ctx, req, &macros); err != nil {
		return nil, err
	}

	return macros, nil

}

func (f *firewallServiceHandler) RemoveGroupVm(ctx context.Context, vmId, groupId string) error {
	path := fmt.Sprintf("%s/detach/group", firewallBasePath)

	removeReq := struct {
		VmID    string `json:"vmId"`
		GroupID string `json:"groupId"`
	}{
		VmID:    vmId,
		GroupID: groupId,
	}

	req, err := f.client.NewRequest(ctx, http.MethodDelete, path, &removeReq)
	if err != nil {
		return err
	}

	return f.client.Do(ctx, req, nil)
}
