package goVPSie

import (
	"context"
	"fmt"
)

var pendingBasePath = "/apps/v2/vm"

type PendingService interface {
	GetPendingVms(ctx context.Context) ([]PendingVm, error)
}

type pendingServiceHandler struct {
	client *Client
}

var _ PendingService = &pendingServiceHandler{}

type PendingVmsRoot struct {
	Error bool        `json:"error"`
	Data  []PendingVm `json:"data"`
}

type PendingVm struct {
	ID   string `json:"id"`
	User struct {
	} `json:"user"`
	UserID int `json:"user_id"`
	Data   struct {
		ResourceIdentifier   string        `json:"resourceIdentifier"`
		OsIdentifier         string        `json:"osIdentifier"`
		DcIdentifier         string        `json:"dcIdentifier"`
		Hostname             string        `json:"hostname"`
		AddPublicIPV4        bool          `json:"addPublicIpV4"`
		AddPublicIPV6        bool          `json:"addPublicIpV6"`
		AddPrivateIP         bool          `json:"addPrivateIp"`
		BackupEnabled        bool          `json:"backupEnabled"`
		WeeklyBackupEnabled  bool          `json:"weeklyBackupEnabled"`
		MonthlyBackupEnabled bool          `json:"monthlyBackupEnabled"`
		Tags                 []interface{} `json:"tags"`
		ProjectID            int           `json:"projectId"`
		VMPassword           string        `json:"vmPassword"`
		ProcessID            string        `json:"processId"`
		SSHKeyIdentifier     string        `json:"sshKeyIdentifier"`
		ScriptIdentifier     string        `json:"scriptIdentifier"`
		IsGeneratedPassword  bool          `json:"isGeneratedPassword"`
		RequestIP            string        `json:"requestIp"`
		IsCreateFromLibrary  bool          `json:"isCreateFromLibrary"`
	} `json:"data"`
	ResourceData struct {
	} `json:"resourceData"`
	Datacenter []interface{} `json:"datacenter"`
	OsData     struct {
	} `json:"osData"`
	Running int    `json:"running"`
	Type    string `json:"type"`
}

func (p *pendingServiceHandler) GetPendingVms(ctx context.Context) ([]PendingVm, error) {
	path := fmt.Sprintf("%s/pending", pendingBasePath)
	req, err := p.client.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	pendingVms := new(PendingVmsRoot)
	if err := p.client.Do(ctx, req, pendingVms); err != nil {
		return nil, err
	}

	return pendingVms.Data, nil
}
