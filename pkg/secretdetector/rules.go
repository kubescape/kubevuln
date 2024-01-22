package secretdetector

import "regexp"

type RegexpDetectionRule struct {
	// The name of the rule
	Name string `json:"name"`
	// The severity of the rule
	Severity string `json:"severity"`
	// Description of the rule
	Description string `json:"description"`
	// The regular expression to match
	Regexp string `json:"regexp"`
}

type CompiledRegexpDetectionRule struct {
	Rule RegexpDetectionRule
	// The compiled regular expression
	Regexp *regexp.Regexp
}

var DefaultRegexpRules = []RegexpDetectionRule{
	{
		Name:        "aws-access-key-id",
		Severity:    "HIGH",
		Description: "AWS Access Key ID",
		Regexp:      "[\"']?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}[\"']?(\\s+|$)",
	},
	{
		Name:        "aws-secret-access-key",
		Severity:    "CRITICAL",
		Description: "AWS Secret Access Key",
		Regexp:      "(?i)(^|\\s+)[\"']?(aws)?_?(sec(ret)?)?_?(access)?_?key[\"']?\\s*(:|=>|=)?\\s*[\"']?[A-Za-z0-9\\/\\+=]{40}[\"']?(\\s+|$)",
	},
	{
		Name:        "github-pat",
		Severity:    "CRITICAL",
		Description: "GitHub Personal Access Token",
		Regexp:      "ghp_[0-9a-zA-Z]{36}",
	},
	{
		Name:        "github-oauth",
		Severity:    "CRITICAL",
		Description: "GitHub OAuth Access Token",
		Regexp:      "gho_[0-9a-zA-Z]{36}",
	},
	{
		Name:        "github-app-token",
		Severity:    "CRITICAL",
		Description: "GitHub App Token",
		Regexp:      "(ghu|ghs)_[0-9a-zA-Z]{36}",
	},
	{
		Name:        "github-refresh-token",
		Severity:    "CRITICAL",
		Description: "GitHub Refresh Token",
		Regexp:      "ghr_[0-9a-zA-Z]{76}",
	},
	{
		Name:        "github-fine-grained-pat",
		Severity:    "CRITICAL",
		Description: "GitHub Fine-grained personal access tokens",
		Regexp:      "github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
	},
	{
		Name:        "gitlab-pat",
		Severity:    "CRITICAL",
		Description: "GitLab Personal Access Token",
		Regexp:      "glpat-[0-9a-zA-Z\\-\\_]{20}",
	},
	{
		Name:        "private-key",
		Severity:    "CRITICAL",
		Description: "PEM Private Key",
		Regexp:      "(?i)-----\\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY( BLOCK)?\\s*?-----[\\s]*?[\\sA-Za-z0-9=+/\\\\\\r\\n]+[\\s]*?-----\\s*?END[ A-Z0-9_-]*? PRIVATE KEY( BLOCK)?\\s*?-----",
	},
	{
		Name:        "shopify-token",
		Severity:    "HIGH",
		Description: "Shopify token",
		Regexp:      "shp(ss|at|ca|pa)_[a-fA-F0-9]{32}",
	},
	{
		Name:        "slack-access-token",
		Severity:    "HIGH",
		Description: "Slack token",
		Regexp:      "xox[baprs]-([0-9a-zA-Z]{10,48})",
	},
	{
		Name:        "stripe-secret-token",
		Severity:    "CRITICAL",
		Description: "Stripe Secret Key",
		Regexp:      "(?i)sk_(test|live)_[0-9a-z]{10,32}",
	},
	{
		Name:        "pypi-upload-token",
		Severity:    "HIGH",
		Description: "PyPI upload token",
		Regexp:      "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,1000}",
	},
	{
		Name:        "gcp-service-account",
		Severity:    "CRITICAL",
		Description: "Google (GCP) Service-account",
		Regexp:      "\\\"type\\\": \\\"service_account\\\"",
	},
	{
		Name:        "heroku-api-key",
		Severity:    "HIGH",
		Description: "Heroku API Key",
		Regexp:      " (?i)(?P<key>heroku[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\\\"]",
	},
	{
		Name:        "alibaba-access-key-id",
		Severity:    "HIGH",
		Description: "Alibaba AccessKey ID",
		Regexp:      "([^0-9A-Za-z]|^)(LTAI)(?i)[a-z0-9]{20}([^0-9A-Za-z]|$)",
	},
	{
		Name:        "alibaba-secret-key",
		Severity:    "HIGH",
		Description: "Alibaba Secret Key",
		Regexp:      "(?i)(?P<key>alibaba[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9]{30}['\\\"]",
	},
	{
		Name:        "atlassian-api-token",
		Severity:    "HIGH",
		Description: "Atlassian API token",
		Regexp:      "(?i)(?P<key>atlassian[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9]{24}['\\\"]",
	},
	{
		Name:        "bitbucket-client-id",
		Severity:    "HIGH",
		Description: "Bitbucket client ID",
		Regexp:      "(?i)(?P<key>bitbucket[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9]{32}['\\\"]",
	},
	{
		Name:        "bitbucket-client-secret",
		Severity:    "HIGH",
		Description: "Bitbucket client secret",
		Regexp:      "(?i)(?P<key>bitbucket[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9_\\-]{64}['\\\"]",
	},
	{
		Name:        "dropbox-api-secret",
		Severity:    "HIGH",
		Description: "Dropbox API secret/key",
		Regexp:      "(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-z0-9]{15})['\\\"]",
	},
	{
		Name:        "dropbox-short-lived-api-token",
		Severity:    "HIGH",
		Description: "Dropbox short lived API token",
		Regexp:      "(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"](sl\\.[a-z0-9\\-=_]{135})['\\\"]",
	},
	{
		Name:        "dropbox-long-lived-api-token",
		Severity:    "HIGH",
		Description: "Dropbox long lived API token",
		Regexp:      "(?i)(dropbox[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43}['\\\"]",
	},
	{
		Name:        "npm-access-token",
		Severity:    "CRITICAL",
		Description: "npm access token",
		Regexp:      "['\\\"](npm_(?i)[a-z0-9]{36})['\\\"]",
	},
	{
		Name:        "pulumi-api-token",
		Severity:    "HIGH",
		Description: "Pulumi API token",
		Regexp:      "pul-[a-f0-9]{40}",
	},
	{
		Name:        "dockerconfig-secret",
		Severity:    "HIGH",
		Description: "Dockerconfig secret exposed",
		Regexp:      "(?i)(\\.(dockerconfigjson|dockercfg):\\s*\\|*\\s*(ey|ew)+[A-Za-z0-9\\/\\+=]+)",
	},
}

func CompileDefaultRegexpRules() ([]CompiledRegexpDetectionRule, error) {
	var compiledRules []CompiledRegexpDetectionRule
	for _, rule := range DefaultRegexpRules {
		compiledRule, err := CompileRegexpDetectionRule(rule)
		if err != nil {
			return nil, err
		}
		compiledRules = append(compiledRules, compiledRule)
	}
	return compiledRules, nil
}

func CompileRegexpDetectionRule(rule RegexpDetectionRule) (CompiledRegexpDetectionRule, error) {
	compiledRegexp, err := regexp.Compile(rule.Regexp)
	if err != nil {
		return CompiledRegexpDetectionRule{}, err
	}
	return CompiledRegexpDetectionRule{
		Rule:   rule,
		Regexp: compiledRegexp,
	}, nil
}
