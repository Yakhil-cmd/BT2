### Title
Webhook signature verification is silently disabled per-organization, allowing unauthenticated forgery of commit statuses and push events - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController` selects which GitHub App's secret is used to verify an inbound webhook based on an attacker-controlled field in the *unverified* JSON body (`repository.owner.login` / `organization.login`), and `GitHubApp#verify_webhook_signature` unconditionally treats the request as authentic whenever that organization has no `webhook_secret` configured. In a multi-organization deployment (the per-organization `secrets.github` schema this engine explicitly supports), any organization onboarded without a webhook secret allows a fully unauthenticated internet client to inject arbitrary `push`, `status`, `check_suite`, `membership`, etc. events for repositories under that organization, with no credential, session, or GitHub signature required.

### Finding Description
`WebhooksController#verify_signature` picks the verifying GitHub App purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the yet-to-be-verified request body before any signature check occurs, and that value is used to pick the `Shipit.github(organization: ...)` app instance whose secret is used for verification, via `Shipit.github_app_config`: [3](#0-2) 

The verification method itself has a fail-open path: [4](#0-3) 

`return true unless webhook_secret` means that for any organization configured without a `webhook_secret`, the HMAC check is skipped entirely — the request is accepted no matter what body or headers are sent. This is not a hypothetical edge case: the engine's own dummy configuration exercises exactly this shape, with one organization carrying a secret and another explicitly configured with `webhook_secret: # nil`: [5](#0-4) 

and the setup docs describe the webhook secret as merely "optional": [6](#0-5) 

Once `verify_signature` passes (trivially, because no secret exists for the impersonated org), `create` re-parses the same untrusted body and dispatches it to registered handlers with no further authentication: [7](#0-6) 

The binding that is broken is: **the organization whose credential (webhook secret) supposedly authenticated the request** vs. **the organization/repository whose state the handlers actually mutate** — the former is nil/absent for that org, so nothing was authenticated at all, yet the latter is fully attacker-controlled. This is the direct analog of `unstreamed` being incremented on `stake` but never decremented on `withdraw`: a public/attacker-influenced counter (here, "was this request verified") is asserted as true for a class of inputs (secret-less orgs) that structurally can never fail the check.

### Impact Explanation
Because `Webhooks::StatusHandler` and `Webhooks::PushHandler` process the forged payload as genuine GitHub data, an attacker can:
- Post a forged `status` event creating a `Status` record with an arbitrary `state` (e.g., `success`) and `context` for any commit SHA on a stack belonging to the secret-less organization, directly manipulating the `ci.require` / `ci.blocking` gating logic in `Shipit::Stack`/`Shipit::Commit` (used to decide whether a commit is safe to deploy).
- Post a forged `push` event pointing at arbitrary refs/SHAs to trigger sync jobs and continuous-delivery evaluation for that stack.

Forging a passing CI status to bypass required-check gating and trigger an unauthorized deploy meets the "unauthorized deploy" Critical/High impact bar, and requires no Shipit session, `ApiClient` token, `webhook_secret` knowledge, or GitHub credentials — only that one onboarded organization lacks a webhook secret, a state the engine itself documents and tests as a supported configuration.

### Likelihood Explanation
Any Shipit deployment onboarding more than one GitHub organization (the per-organization secrets schema) and following the documented guidance that the webhook secret is "optional" for at least one of them is exposed. No attacker secret or privileged access is needed — only the target organization's login name, which is public.

### Recommendation
- Require `webhook_secret` to be present for every configured organization at boot/config-validation time; refuse to start (or refuse to serve that org's webhooks) if it is missing, rather than treating a missing secret as "skip verification."
- Do not derive the verifying organization from unauthenticated payload fields; if per-organization secrets are required, verify against all configured secrets (or bind the webhook endpoint to a specific org) rather than trusting `repository.owner.login`/`organization.login` before verification.

### Proof of Concept
1. Deploy Shipit with the per-organization `secrets.github` schema, where `OrgTwo` has `webhook_secret: nil` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Send, with no valid GitHub signature:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<target-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"full_name": "OrgTwo/some-repo", "owner": {"login": "OrgTwo"}}
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgTwo").verify_webhook_signature(...)`, which returns `true` immediately because `OrgTwo`'s `webhook_secret` is blank [8](#0-7) .
4. `Webhooks::StatusHandler` processes the forged payload and creates/updates a `Status` on the target commit as if GitHub had reported it, satisfying `ci.require` for a deploy the attacker never actually built or reviewed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
