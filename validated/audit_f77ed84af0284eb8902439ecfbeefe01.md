## Title
Cross-organization webhook secret confusion allows forged CI status injection for any commit / stack — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/webhook secret to validate a webhook against using `repository_owner`, a value read directly out of the unauthenticated JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). The handlers that actually act on the payload (e.g. `StatusHandler`, `PushHandler`, and the `pull_request` handlers) instead key off a *different* attacker-controlled field — `repository.full_name` (or, for `StatusHandler`, no repository scoping at all, just a raw commit `sha`). Because Shipit explicitly supports multiple GitHub Apps/organizations, each with its own (optionally unset) `webhook_secret`, the org used to select the verifying secret and the resource that ends up mutated are never checked for consistency.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is taken from the payload itself [2](#0-1) . `Shipit.github` resolves per-organization config via `github_app_config(organization)` [3](#0-2) , and Shipit explicitly documents multi-org setups where each org has its own, independently-configured (and possibly absent) `webhook_secret` [4](#0-3) . `verify_webhook_signature` trivially returns `true` when that org has no `webhook_secret` configured: [5](#0-4) .

Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire* attacker-controlled body to a handler [6](#0-5) . The handler classes look up the affected `Stack`/`Repository` from a completely separate field, `repository.full_name` [7](#0-6) . `StatusHandler` is the most severe: it does not scope by repository at all, and directly persists attacker-supplied `state`/`description`/`context`/`target_url` onto any `Commit` matching the attacker-chosen `sha`, regardless of stack or organization: [8](#0-7) .

This breaks exactly the binding called out in scope: *"an organization that authenticated versus the repository that is written."* The value used to pick the verifying secret (`repository.owner.login`) is never checked against the value used to select the repository/commit that is mutated (`repository.full_name` / bare `sha`).

### Impact Explanation
On any Shipit instance configured with multiple GitHub Apps (a documented, supported configuration [4](#0-3) ), an unauthenticated attacker who can send an HTTP request to `/webhooks` (no session, no API token needed) can:
- pick `repository.owner.login` = any org configured in this Shipit instance that has no `webhook_secret` set (satisfying `verify_webhook_signature`'s trivial pass), while
- setting `repository.full_name` / `sha` to target a *different* org's tracked repository/commit that they do not control.

This lets the attacker inject a fabricated GitHub commit status for an arbitrary commit SHA tracked by Shipit. Since CI status gating (`ci.require`) determines whether a commit is `deployable?`, a forged "success" status can help bypass CI requirements gating deploys — an escalation toward unauthorized deploys. Even absent full deploy bypass, this is at minimum an unauthenticated cross-organization write into another organization's stack state (falsified CI/status history), which matches the "escalation into authorization boundaries" / "unauthorized deploy" class of impact called out in scope.

### Likelihood Explanation
Likelihood is contingent on the deployment having more than one GitHub App/org configured (a first-class, documented feature) and at least one configured org lacking a `webhook_secret` (webhook secret is explicitly documented as "optional"). Given that condition, exploitation requires no credentials, no session, no repository access — just an HTTP POST to the public `/webhooks` endpoint with a crafted event and mismatched `owner.login` / `full_name` fields.

### Recommendation
- After selecting the GitHub App by `repository_owner`, verify that the *repository actually referenced in the handler-relevant payload fields* (`repository.full_name`, or the owner implied by any `sha` lookup) belongs to that same, verified organization before dispatching to handlers.
- In `StatusHandler`, scope the `Commit` lookup by the verified organization/repository, not solely by `sha`.
- Do not allow `verify_webhook_signature` to silently succeed when `webhook_secret` is unset if multiple organizations are configured; require an explicit secret per org in multi-tenant mode.

### Proof of Concept
Preconditions: Shipit instance configured with two GitHub Apps, `OrgA` (no `webhook_secret` set) and `OrgB` (tracks `OrgB/victim-repo`, with commit `deadbeef` requiring CI status `ci-required-context` for deploy).

1. Attacker sends, unauthenticated:
```
POST /webhooks
X-Github-Event: status
(no valid X-Hub-Signature needed, since OrgA has no webhook_secret)

{
  "sha": "deadbeef",
  "state": "success",
  "context": "ci-required-context",
  "repository": { "full_name": "OrgB/attacker-doesnt-need-this", "owner": { "login": "OrgA" } }
}
```
2. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally [5](#0-4) .
3. `StatusHandler#process` then runs unscoped: `Commit.where(sha: "deadbeef").each { |commit| commit.create_status_from_github!(params) }` [8](#0-7) , forging a passing CI status on `OrgB`'s commit despite the request never being authenticated against `OrgB`'s secret.

Note: I was unable to fully trace `Commit#create_status_from_github!` and `Commit#deployable?` in this session (ran out of iterations before reading `app/models/shipit/commit.rb`/`app/models/shipit/status.rb` directly) — I found references confirming these methods exist via grep, but did not verify line-by-line how `deployable?` consumes `Status` records to gate `ci.require`. This should be confirmed before treating "bypasses CI-gated deploys" as fully proven; the cross-organization signature/authorization-selection bug itself (verified secret's org ≠ mutated repository's org) is confirmed directly from the cited files.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
