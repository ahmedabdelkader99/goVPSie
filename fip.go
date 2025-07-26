package goVPSie

import (
	"context"
	"fmt"
	"net/http"
)

var fipBasePath = "/apps/v2/fip"

type FipService interface {
	AssignFloatingIP(context.Context) error
	UnassignFloatingIP(ctx context.Context, id string) error
	CreateFloatingIP(ctx context.Context, vmIdentifier, dcIdentifier, ipType string) error
}

type fipServiceHandler struct {
	client *Client
}

var _ FipService = &fipServiceHandler{}

func (f *fipServiceHandler) AssignFloatingIP(ctx context.Context) error {
	path := fmt.Sprintf("%s/create/ranges", fipBasePath)

	req, err := f.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}

	return f.client.Do(ctx, req, nil)
}

func (f *fipServiceHandler) UnassignFloatingIP(ctx context.Context, id string) error {
	path := fmt.Sprintf("%s/remove/public/ip", fipBasePath)

	anassignReq := struct {
		ID                    string `json:"id"`
		RemoveFromUserAccount string `json:"removeFromUserAccount"`
	}{
		ID:                    id,
		RemoveFromUserAccount: "0",
	}

	req, err := f.client.NewRequest(ctx, http.MethodDelete, path, &anassignReq)
	if err != nil {
		return err
	}

	return f.client.Do(ctx, req, nil)
}

func (f *fipServiceHandler) CreateFloatingIP(ctx context.Context, vmIdentifier, dcIdentifier, ipType string) error {
	crateReq := struct {
		VmIdentifier string `json:"vmIdentifier"`
		DcIdentifier string `json:"dcIdentifier"`
		IpType       string `json:"ipType"`
	}{
		VmIdentifier: vmIdentifier,
		DcIdentifier: dcIdentifier,
		IpType:       ipType,
	}

	path := fmt.Sprintf("%s/add/public/ip", fipBasePath)
	req, err := f.client.NewRequest(ctx, http.MethodPost, path, &crateReq)
	if err != nil {
		return err
	}

	return f.client.Do(ctx, req, nil)

}
