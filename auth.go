package linkedinchallenge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"net/http"
	"strings"
	"time"
)

const (
	seedURL   string = "https://www.linkedin.com/uas/login"
	loginURL  string = "https://www.linkedin.com/checkpoint/lg/login-submit"
	verifyURL string = "https://www.linkedin.com/checkpoint/challenge/verify"
)

type Client struct {
	email      string
	password   string
	httpClient *http.Client
	csrfToken  string
}

func NewClient(email string, password string) Client {
	return Client{
		email:      email,
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		csrfToken:  "",
	}
}

func (c *Client) ensureInitialized() error {
	missing := make([]string, 0, 2)

	if c.email == "" {
		missing = append(missing, "email")
	}

	if c.password == "" {
		missing = append(missing, "password")
	}

	if len(missing) > 0 {
		return fmt.Errorf("%s missing in Client struct", strings.Join(missing, ", "))
	}

	// the client seems to be not initialized
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return nil
}

func (c *Client) Seed() error {
	err := c.ensureInitialized()
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Get(seedURL)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return err
	}

	csrfToken := extractValue(d, `input[name="loginCsrfParam"]`)
	if csrfToken == "" {
		return fmt.Errorf("request did not return csrf token")
	}

	c.csrfToken = csrfToken

	return nil
}

type loginPayload struct {
	SessionKey      string `json:"session_key"`
	CSRFToken       string `json:"loginCsrfParam"`
	SessionPassword string `json:"session_password"`
}

type LoginResponse struct {
	ActionsNeeded bool   `json:"actionsNeeded"`
	CSRFToken     string `json:"csrfToken"`
	PageInstance  string `json:"pageInstance"`
	// the following fields are typically missing if no actions are needed
	ResendURL           string `json:"resendUrl,omitempty"`
	ChallengeID         string `json:"challengeId,omitempty"`
	Language            string `json:"language,omitempty"`
	DisplayTime         string `json:"displayTime,omitempty"`
	ChallengeSource     string `json:"challengeSource,omitempty"`
	RequestSubmissionId string `json:"requestSubmissionId,omitempty"`
	ChallengeType       string `json:"challengeType,omitempty"`
	ChallengeData       string `json:"challengeData,omitempty"`
	ChallengeDetails    string `json:"challengeDetails,omitempty"`
	FailureRedirectURI  string `json:"failureRedirectUrl,omitempty"`
}

func (c *Client) Login() (LoginResponse, error) {
	err := c.ensureInitialized()
	if err != nil {
		return LoginResponse{}, err
	}

	if c.csrfToken == "" {
		return LoginResponse{}, fmt.Errorf("csrf token is missing")
	}

	payload := loginPayload{
		SessionKey:      c.email,
		CSRFToken:       c.csrfToken,
		SessionPassword: c.password,
	}

	params, err := json.Marshal(payload)
	if err != nil {
		return LoginResponse{}, err
	}

	request, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(params))
	if err != nil {
		return LoginResponse{}, err
	}

	resp, err := c.httpClient.Do(request)
	if err != nil {
		return LoginResponse{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginResponse{}, fmt.Errorf("auth failed. status code is %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return LoginResponse{}, err
	}

	challengeType := extractValue(d, `input[name="challengeType"]`)
	challengeData := extractValue(d, `input[name="challengeData"]`)
	challengeDetails := extractValue(d, `input[name="challengeDetails"]`)

	actionsNeeded := false

	if challengeType == "" && challengeData == "" && challengeDetails == "" {
		actionsNeeded = true
	}

	return LoginResponse{
		CSRFToken:           extractValue(d, `input[name="csrfToken"]`),
		PageInstance:        extractValue(d, `input[name="pageInstance"]`),
		ResendURL:           extractValue(d, `input[name="resendUrl"]`),
		ChallengeID:         extractValue(d, `input[name="challengeId"]`),
		Language:            "en-US",
		DisplayTime:         extractValue(d, `input[name="displayTime"]`),
		ChallengeSource:     extractValue(d, `input[name="challengeSource"]`),
		RequestSubmissionId: extractValue(d, `input[name="requestSubmissionId"]`),
		ChallengeType:       challengeType,
		ChallengeData:       challengeData,
		ChallengeDetails:    challengeDetails,
		FailureRedirectURI:  extractValue(d, `input[name="failureRedirectUri"]`),
		ActionsNeeded:       actionsNeeded,
	}, nil
}

type VerifyPayload struct {
	LoginResponse
	PIN string `json:"pin"`
}

func (c *Client) Verify(p VerifyPayload) error {
	err := c.ensureInitialized()
	if err != nil {
		return err
	}

	if p.CSRFToken == "" {
		return fmt.Errorf("csrf token is missing")
	}

	if p.PageInstance == "" {
		return fmt.Errorf("page instance is missing")
	}

	if p.PIN == "" {
		return fmt.Errorf("pin is missing")
	}

	params, err := json.Marshal(p)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", verifyURL, bytes.NewBuffer(params))
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verify request did not succeed")
	}

	return nil
}
