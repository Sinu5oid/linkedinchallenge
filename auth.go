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
	Email      string `json:"email"`
	Password   string `json:"password"`
	httpClient *http.Client
	csrfToken  string
}

func NewClient(email string, password string) Client {
	return Client{
		Email:      email,
		Password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		csrfToken:  "",
	}
}

func (c *Client) ensureInitialized() error {
	missing := make([]string, 0, 2)

	if c.Email == "" {
		missing = append(missing, "email")
	}

	if c.Password == "" {
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

	csrfToken := ExtractValue(d, `input[name="loginCsrfParam"]`)
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
		SessionKey:      c.Email,
		CSRFToken:       c.csrfToken,
		SessionPassword: c.Password,
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

	challengeType := ExtractValue(d, `input[name="challengeType"]`)
	challengeData := ExtractValue(d, `input[name="challengeData"]`)
	challengeDetails := ExtractValue(d, `input[name="challengeDetails"]`)

	actionsNeeded := false

	if challengeType == "" && challengeData == "" && challengeDetails == "" {
		actionsNeeded = true
	}

	return LoginResponse{
		CSRFToken:           ExtractValue(d, `input[name="csrfToken"]`),
		PageInstance:        ExtractValue(d, `input[name="pageInstance"]`),
		ResendURL:           ExtractValue(d, `input[name="resendUrl"]`),
		ChallengeID:         ExtractValue(d, `input[name="challengeId"]`),
		Language:            "en-US",
		DisplayTime:         ExtractValue(d, `input[name="displayTime"]`),
		ChallengeSource:     ExtractValue(d, `input[name="challengeSource"]`),
		RequestSubmissionId: ExtractValue(d, `input[name="requestSubmissionId"]`),
		ChallengeType:       challengeType,
		ChallengeData:       challengeData,
		ChallengeDetails:    challengeDetails,
		FailureRedirectURI:  ExtractValue(d, `input[name="failureRedirectUri"]`),
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
