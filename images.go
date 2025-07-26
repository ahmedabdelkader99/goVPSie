package goVPSie

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

var imagesPath = "/apps/v2/custom"

type ImagesService interface {
	DeleteImage(ctx context.Context, imageIdentifier string) error
	List(ctx context.Context, options *ListOptions) ([]CustomImage, error)
	CreateImages(ctx context.Context, dcIdentifier, imageName, imageUrl string) error
	CreateServerByImage(ctx context.Context, createServerReq *CreateServerRequest) error
	GetImage(ctx context.Context, imageIdentifier string) (*CustomImage, error)
}

type imagesServiceHandler struct {
	client *Client
}

var _ ImagesService = &imagesServiceHandler{}

type ListCustomImageRoot struct {
	Error bool          `json:"error"`
	Data  []CustomImage `json:"data"`
	Total int           `json:"total "`
}

type CustomImage struct {
	ID             int       `json:"id"`
	UserID         int       `json:"user_id"`
	DatacenterID   int       `json:"datacenter_id"`
	ImageSize      int64     `json:"image_size"`
	OriginalName   string    `json:"original_name"`
	FetchedFromURL string    `json:"fetched_from_url"`
	ChangedName    string    `json:"changed_name"`
	ImageHash      string    `json:"image_hash"`
	ImageLabel     string    `json:"image_label"`
	CreatedOn      time.Time `json:"created_on"`
	Deleted        int       `json:"deleted"`
	Identifier     string    `json:"identifier"`
	Storage        string    `json:"storage"`
	DcName         string    `json:"dc_name"`
	DcIdentifier   string    `json:"dcIdentifier"`
	CreatedBy      string    `json:"created_by"`
}

func (i *imagesServiceHandler) List(ctx context.Context, options *ListOptions) ([]CustomImage, error) {
	path := fmt.Sprintf("%s/images", imagesPath)

	req, err := i.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	images := new(ListCustomImageRoot)
	if err = i.client.Do(ctx, req, images); err != nil {
		return nil, err
	}

	return images.Data, nil
}

func (i *imagesServiceHandler) CreateImages(ctx context.Context, dcIdentifier, imageName, imageUrl string) error {
	path := fmt.Sprintf("%s/images", imagesPath)

	createReq := struct {
		DcIdentifier string `json:"dcIdentifier"`
		ImageName    string `json:"imageName"`
		ImageUrl     string `json:"imageUrl"`
	}{
		DcIdentifier: dcIdentifier,
		ImageName:    imageName,
		ImageUrl:     imageUrl,
	}
	req, err := i.client.NewRequest(ctx, http.MethodPost, path, createReq)
	if err != nil {
		return err
	}

	if err = i.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}

func (i *imagesServiceHandler) DeleteImage(ctx context.Context, imageIdentifier string) error {
	path := fmt.Sprintf("%s/images/%s", imagesPath, imageIdentifier)

	req, err := i.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	if err = i.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}

func (i *imagesServiceHandler) CreateServerByImage(ctx context.Context, createServerReq *CreateServerRequest) error {
	path := fmt.Sprintf("%s/vm", imagesPath)
	req, err := i.client.NewRequest(ctx, http.MethodPost, path, createServerReq)
	if err != nil {
		return err
	}

	if err = i.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}

func (i *imagesServiceHandler) GetImage(ctx context.Context, imageIdentifier string) (*CustomImage, error) {
	path := fmt.Sprintf("%s/images/?imageIdentifier=%s", imagesPath, imageIdentifier)

	req, err := i.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	image := new(ListCustomImageRoot)
	if err = i.client.Do(ctx, req, image); err != nil {
		return nil, err
	}

	if len(image.Data) == 0 {
		return nil, fmt.Errorf("image not found")
	}

	return &image.Data[0], nil
}
