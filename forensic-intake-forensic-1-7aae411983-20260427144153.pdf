# Customer Research Helper Technical Security Report

- Organization: Acme Security
- Extension ID: demo-customer-research-helper
- Store: Chrome Web Store
- Version: 2.7.1
- Risk score: 100/100
- Scan completed: 2026-04-26 06:55:51.701964+00:00

## Executive Summary

Critical posture: quarantine or emergency review recommended. 13 finding(s) detected.

## Severity Distribution

- Critical: 1
- High: 8
- Medium: 4
- Low: 0
- Info: 0

## Findings

### Critical - Critical permission requested: nativeMessaging

Category: Permission

Communicate with local native applications.

Recommendation: Remove this permission or isolate it behind a strongly justified enterprise policy exception.

Evidence: `{'permission': 'nativeMessaging'}`

### High - Extension update URL is not HTTPS

Category: Supply Chain

Non-HTTPS update channels are vulnerable to tampering.

Recommendation: Serve update manifests and packages only over HTTPS from a controlled domain.

Evidence: `{'update_url': 'http://updates.example.com/extension.xml'}`

### High - Content Security Policy allows unsafe eval

Category: Content Security Policy

Eval-like execution increases exploitability if extension code handles hostile input.

Recommendation: Remove unsafe-eval and use static script bundles with strict CSP.

Evidence: `{'content_security_policy': "script-src 'self' 'unsafe-eval' http://cdn.example.com; object-src 'self'"}`

### High - Externally connectable policy accepts broad origins

Category: External Connectivity

Broad externally_connectable origins can expose extension messaging to untrusted websites.

Recommendation: Allow only exact trusted origins for extension messaging.

Evidence: `{'externally_connectable.matches': ['*']}`

### High - Broad host permissions allow access across large browsing surfaces

Category: Host Access

The extension can run against all or nearly all browser destinations.

Recommendation: Constrain host permissions to business-approved domains and request optional access only when needed.

Evidence: `{'host_permissions': ['<all_urls>']}`

### High - High-risk permission requested: webRequest

Category: Permission

Observe network requests.

Recommendation: Replace broad permissions with optional permissions or a narrower extension architecture.

Evidence: `{'permission': 'webRequest'}`

### High - High-risk permission requested: tabs

Category: Permission

Read browser tab metadata and URLs.

Recommendation: Replace broad permissions with optional permissions or a narrower extension architecture.

Evidence: `{'permission': 'tabs'}`

### High - High-risk permission requested: history

Category: Permission

Read browsing history.

Recommendation: Replace broad permissions with optional permissions or a narrower extension architecture.

Evidence: `{'permission': 'history'}`

### High - High-risk permission requested: downloads

Category: Permission

Access downloaded file events and metadata.

Recommendation: Replace broad permissions with optional permissions or a narrower extension architecture.

Evidence: `{'permission': 'downloads'}`

### Medium - High install base amplifies security impact

Category: Exposure

A high-risk extension with a large install base can affect many users quickly.

Recommendation: Prioritize remediation, targeted allow-listing, or staged quarantine for this extension.

Evidence: `{'install_base': 185000}`

### Medium - Content Security Policy references insecure HTTP

Category: Content Security Policy

HTTP resource references can be modified in transit.

Recommendation: Use HTTPS-only resources and avoid remote script execution.

Evidence: `{'content_security_policy': "script-src 'self' 'unsafe-eval' http://cdn.example.com; object-src 'self'"}`

### Medium - Content scripts match broad URL patterns

Category: Content Script

Broad content-script matching increases data exposure if the script is compromised.

Recommendation: Limit content scripts to explicit domains and avoid automatic injection on sensitive sites.

Evidence: `{'matches': ['<all_urls>']}`

### Medium - Extension is not using Manifest V3

Category: Manifest

Manifest V2 or missing manifest version increases review and lifecycle risk.

Recommendation: Migrate the extension to Manifest V3 and remove deprecated APIs.

Evidence: `{'manifest_version': 2}`
