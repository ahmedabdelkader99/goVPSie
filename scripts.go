package goVPSie

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

var scriptsBasePath = "/apps/v2"

type ScriptsService interface {
	GetScripts(ctx context.Context) ([]Script, error)
	GetScript(ctx context.Context, scriptId string) (ScriptDetail, error)
	CreateScript(ctx context.Context, createScriptRequest *CreateScriptRequest) error
	UpdateScript(ctx context.Context, scriptUpdateRequest *ScriptUpdateRequest) error
	DeleteScript(ctx context.Context, scriptId string) error
}

type scriptsServiceHandler struct {
	client *Client
}

var _ ScriptsService = &scriptsServiceHandler{}

type Script struct {
	UserID        int       `json:"user_id"`
	BoxID         int       `json:"box_id"`
	BoxIdentifier string    `json:"box_identifier"`
	ScriptName    string    `json:"script_name"`
	Script        string    `json:"script"`
	CreatedOn     time.Time `json:"created_on"`
	Identifier    string    `json:"identifier"`
	CreatedBy     string    `json:"created_by"`
}

type ScriptDetail struct {
	ID            int       `json:"id"`
	UserID        int       `json:"user_id"`
	BoxID         int       `json:"box_id"`
	BoxIdentifier string    `json:"box_identifier"`
	Name          string    `json:"name"`
	Script        string    `json:"script"`
	CreatedOn     time.Time `json:"created_on"`
	Identifier    string    `json:"identifier"`
	ScriptName    string    `json:"script_name"`
	Type          string    `json:"type"`
}

type CreateScriptRequest struct {
	Name          string   `json:"name"`
	ScriptContent string   `json:"scriptContent"`
	ScriptType    string   `json:"scriptType"`
	Tags          []string `json:"tags"`
}

type ListScriptRoot struct {
	Error bool     `json:"error"`
	Data  []Script `json:"data"`
	Total int      `json:"total"`
}

type ScriptUpdateRequest struct {
	Name             string `json:"name"`
	ScriptContent    string `json:"scriptContent"`
	ScriptIdentifier string `json:"scriptIdentifier"`
	ScriptType       string `json:"scriptType"`
}

type ScriptRoot struct {
	Error bool         `json:"error"`
	Data  ScriptDetail `json:"data"`
}

func (s *scriptsServiceHandler) GetScripts(ctx context.Context) ([]Script, error) {
	path := fmt.Sprintf("%s/scripts", scriptsBasePath)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	scripts := new(ListScriptRoot)
	if err := s.client.Do(ctx, req, scripts); err != nil {
		return nil, err
	}

	return scripts.Data, nil
}

func (s *scriptsServiceHandler) GetScript(ctx context.Context, scriptId string) (ScriptDetail, error) {
	path := fmt.Sprintf("%s/script/%s", scriptsBasePath, scriptId)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return ScriptDetail{}, err
	}
	script := new(ScriptRoot)
	if err := s.client.Do(ctx, req, script); err != nil {
		return ScriptDetail{}, err
	}

	return script.Data, nil
}

func (s *scriptsServiceHandler) CreateScript(ctx context.Context, createScriptRequest *CreateScriptRequest) error {
	path := fmt.Sprintf("%s/script/add", scriptsBasePath)

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, createScriptRequest)
	if err != nil {
		return err
	}

	if err := s.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}

func (s *scriptsServiceHandler) UpdateScript(ctx context.Context, scriptUpdateRequest *ScriptUpdateRequest) error {
	path := fmt.Sprintf("%s/script/edit", scriptsBasePath)

	req, err := s.client.NewRequest(ctx, http.MethodPut, path, scriptUpdateRequest)
	if err != nil {
		return err
	}

	if err := s.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}

func (s *scriptsServiceHandler) DeleteScript(ctx context.Context, scriptId string) error {
	path := fmt.Sprintf("%s/script", scriptsBasePath)

	deltReq := struct {
		ScriptIdentifier string `json:"scriptIdentifier"`
	}{
		ScriptIdentifier: scriptId,
	}

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, &deltReq)
	if err != nil {
		return err
	}

	if err := s.client.Do(ctx, req, nil); err != nil {
		return err
	}

	return nil
}
