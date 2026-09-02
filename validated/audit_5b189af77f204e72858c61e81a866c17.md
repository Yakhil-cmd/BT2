### Title
Webhook signature verification is bound to `repository.owner.login`, but every event handler acts on the independently-attacker-controlled `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to check the `X-Hub-Signature` against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')`. Every event `Handler` (push, status, check_suite, pull_request, membership) instead resolves the target `Repository`/`Stack` using a *different* payload field, `payload.dig('repository', 'full_name')` in `Handler#repository_name`. These two fields are never checked for consistency, and both come from the same unauthenticated, attacker-supplied JSON body. In a multi-organization deployment (`config/secrets.yml` `github:` keyed by org), an attacker can pick an organization key whose `webhook_secret` is blank/unset to trivially satisfy `verify_webhook_signature` (which does `return true unless webhook_secret`), while setting `repository.full_name` to any other tracked organization/repository — including one that *does* have a webhook secret configured — and have the handler act on it.

### Finding Description
- Signature verification: `Shipit::WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then does `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 

- `verify_webhook_signature` explicitly no-ops when no secret is configured for that org: `return true unless webhook_secret`. [3](#0-2) 

- `Shipit.github(organization:)` resolves per-organization config (`github_app_config(organization)`), so in multi-org mode each org key can have its own, independently blank-or-set `webhook_secret`. [4](#0-3) 

- All event handlers, however, resolve the *acted-upon* repository from a separate field: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `Handler#stacks` uses `Repository.from_github_repo_name(repository_name)`. [5](#0-4) 

- Concretely, `PushHandler#process` calls `stack.sync_github(...)` for every matching stack derived from that `full_name` lookup, `StatusHandler#process` updates commit statuses for `params.sha` regardless of owner, and `CheckSuiteHandler#process` schedules check-run refreshes for stacks matched via the same `full_name`-derived `stacks` helper. [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization_whose_secret_verified_the_signature == owner(repository_acted_upon)`

Before the attack: this equality trivially holds because in a legitimate GitHub-relayed webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always the same value, both populated by GitHub itself.

After the attacker's crafted request: the attacker fully controls both fields independently (there is no GitHub relay — anyone can `POST /webhooks` directly with `X-Github-Event` and `X-Hub-Signature` headers of their choosing). They set `repository.owner.login` to an organization key configured in `secrets.yml` with an empty/absent `webhook_secret` (satisfying `verify_signature` for free per the `return true unless webhook_secret` short-circuit), while setting `repository.full_name` to `victim-org/protected-repo` — a repository tracked under a *different* organization key that *does* have a real secret configured. The equality is broken: verification authenticated organization A, but the handler mutates/acts on state belonging to organization B's repository.

### Impact Explanation
This is a High-severity authentication-boundary bypass: it allows an unauthenticated attacker to forge trusted GitHub webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`) for a protected/HMAC-secured repository by routing the signature check through an unrelated, secret-less organization. Concrete consequences per handler:
- `PushHandler` can trigger `stack.sync_github(expected_head_sha: ...)` for the victim's stacks, influencing what commit is considered "head" and queuing sync jobs — an unauthenticated write into deployable state for a stack the attacker never proved control of. [6](#0-5) 
- `StatusHandler` can forge CI status entries (`create_status_from_github!`) on real commits, which downstream deploy-safety logic (`ci.require` checks) relies on to gate deploys — enabling an unauthorized ship by faking green CI. [7](#0-6) 
- `CheckSuiteHandler` can force re-fetching of check runs for arbitrary commits/stacks. [8](#0-7) 

This matches the rubric's "unauthorized deploy" impact class, since forged status webhooks can flip a commit's CI status used to gate `deploy` eligibility.

### Likelihood Explanation
Requires: (1) the deployment to use the multi-organization `github:` secrets schema, and (2) at least one configured organization key with no `webhook_secret` set (documented in `docs/setup.md` as "optional") while another organization/repo the attacker wants to target does have one set. This is a realistic, documented configuration (webhook secret is explicitly optional per-org), not an edge case requiring host misconfiguration outside the documented setup. No credentials, GitHub App keys, or Shipit session are required — only the ability to POST directly to the public `/webhooks` endpoint.

### Recommendation
Verify the signature using the secret associated with the *same* field that handlers use to resolve the target repository (`repository.full_name`'s owner segment), not a separately-controlled `repository.owner.login`/`organization.login` field. Additionally/alternatively, after verifying, re-derive `repository_owner` strictly from `repository.full_name` and assert it matches the value used to select the signing secret before dispatching to handlers, rejecting the request if they diverge.

### Proof of Concept
1. Deploy Shipit with a multi-org `github:` config: org `empty-org` (no `webhook_secret` set) and org `victim-org` (has `webhook_secret` set, and has a tracked `Repository`/`Stack` for `victim-org/protected-repo`).
2. Send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted
Content-Type: application/json

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "victim-org/protected-repo",
    "owner": { "login": "empty-org" }
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'empty-org')`; `verify_webhook_signature` returns `true` immediately because `empty-org`'s `webhook_secret` is blank — no valid HMAC is required. [3](#0-2) 
4. `StatusHandler#process` (dispatched via `Shipit::Webhooks.for_event(event)` in `WebhooksController#create`) resolves `Commit.where(sha: params.sha)` and calls `create_status_from_github!`, writing a forged "success" status onto the victim commit, entirely bypassing `victim-org`'s configured webhook secret. [9](#0-8) [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
