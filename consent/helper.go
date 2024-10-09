// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package consent

import (
	"net/url"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/flow"
)

func sanitizeClientFromRequest(ar fosite.AuthorizeRequester) *client.Client {
	return sanitizeClient(ar.GetClient().(*client.Client))
}

func sanitizeClient(c *client.Client) *client.Client {
	cc := new(client.Client)
	// Remove the hashed secret here
	*cc = *c
	cc.Secret = ""
	return cc
}

func matchScopes(scopeStrategy fosite.ScopeStrategy, previousConsent []flow.AcceptOAuth2ConsentRequest, requestedScope []string) *flow.AcceptOAuth2ConsentRequest {
	for _, cs := range previousConsent {
		var found = true
		for _, scope := range requestedScope {
			if !scopeStrategy(cs.GrantedScope, scope) {
				found = false
				break
			}
		}

		if found {
			return &cs
		}
	}

	return nil
}

func getQueryParamsHavingPrefix(rawURL string, prefix string) (url.Values, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return url.Values{}, err
	}

	queryParams := parsedURL.Query()
	filteredParams := url.Values{}

	for key, values := range queryParams {
		if strings.HasPrefix(key, prefix) {
			filteredParams[key] = values
		}
	}

	return filteredParams, nil
}
