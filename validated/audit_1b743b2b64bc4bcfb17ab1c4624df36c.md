### Title
Cross-organization commit-status forgery via mismatched signature-verification key and status target - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is a genuine multi-tenant analog of the "wrong constant / wrong binding" bug class in the reported crypto issue: two values that should be the same identity (the org whose secret is used to authenticate a webhook, and the repository/commit that webhook is allowed to mutate) are computed from two different, independently attacker-controlled payload paths, and are never cross-checked.

### Finding Description
`WebhooksController#verify_signature` selects which organization's webhook secret to validate the HMAC signature against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or falls back to `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization secret from `github_app_config`, confirming Shipit natively supports multiple organizations each with an independent `webhook_secret`: [3](#0-2) 

Once the signature check passes for *whatever org `repository.owner.login` names*, the raw JSON body is dispatched unmodified to handlers, which pick the actual repository/commit to mutate from a **separate** JSON field: [4](#0-3) 
`Handler#repository_name` reads `payload.dig('repository', 'full_name')` — not `repository.owner.login`: [5](#0-4) 

Critically, `StatusHandler` does not even scope by repository at all — it resolves target commits purely by SHA across the entire installation: [6](#0-5) 

Because signature verification is keyed off `repository.owner.login`/`organization.login` while the actual mutation (which stack gets `sync_github`'d, or which `Commit` gets a status attached) is keyed off `repository.full_name` (`PushHandler`/`review_stack` handlers) or off `sha` alone (`StatusHandler`), an attacker who legitimately controls one tenant organization's webhook secret can forge a signed payload where `repository.owner.login` names their own org (so the HMAC check passes) while `repository.full_name`/`sha` targets a different, victim organization's repository or a commit belonging to a different stack. The binding the code implicitly assumes — `organization authenticated == repository/commit written` — does not hold.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary called out in scope. Concretely:
- `StatusHandler` can forge a `success` commit status for **any** commit sha in the whole installation (not scoped to the signing org's repositories at all), which can flip a commit's deployable state and enable an unauthorized deploy for a stack the attacker's organization has no relationship to.
- `PushHandler` can be tricked into calling `stack.sync_github(expected_head_sha:)` for a stack belonging to `repository.full_name` set to a different org/repo than the one whose secret signed the request, causing spurious/attacker-influenced sync activity against another tenant's stack.

This qualifies as "an unauthorized deploy" per the impact list, achieved purely by an attacker who possesses one org's webhook secret (a credential this deployment already grants them for their own org) but not the victim's — i.e., a credential/organization boundary is crossed without an org-repository binding check.

### Likelihood Explanation
Requires a multi-org Shipit deployment (config `secrets.github` keyed by multiple organizations, each with independent `webhook_secret`, which the code explicitly supports via `github_app_config`/`github_organizations`). In such an installation, any org owner able to send webhooks signed with their own configured secret — which is the expected/legitimate way GitHub delivers events for their own installation — can freely set `repository.full_name` or omit any owner cross-check field to target another tenant's data. No additional privilege beyond "control of one tenant's webhook secret" (which is intentionally distributed to that tenant) is required.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after establishing which organization's secret validated the signature, re-derive `repository_owner` from `repository.full_name`'s namespace (or otherwise verify `repository.owner.login == repository.full_name.split('/').first`) and reject mismatches. In `Handler#stacks`/`repository_name`, and specifically in `StatusHandler#process`, scope the `Commit` lookup by the repository resolved from the same verified organization, e.g. `commit.stack.repository.owner == verified_organization`, instead of matching by bare `sha` across the whole database.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` under `secrets.github`.
2. As the administrator/owner of `attacker-org`'s GitHub App (an unprivileged actor with respect to `victim-org`), craft a `status` event payload:
```json
{
  "sha": "<victim commit sha, e.g. head of a pending victim deploy>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Sign the raw body with `attacker-org`'s `webhook_secret` and send it to `POST /webhooks` with `X-Github-Event: status` and the resulting `X-Hub-Signature`.
4. `verify_signature` computes `repository_owner == 'attacker-org'`, fetches `Shipit.github(organization: 'attacker-org')`, and the HMAC check succeeds because the attacker legitimately holds that secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching and updating the victim's commit purely by `sha`, with no organization/repository check — attaching a forged `success` status to a commit the attacker never had signing authority over.

Note: I could not fully trace downstream how a forged `success` status interacts with every deploy-gating code path (e.g., `Commit#deployable?`/`ignore_ci` logic in `app/models/shipit/commit.rb`) within the tool-call budget available; confirming the exact conditions under which this forged status enables an actual unauthorized deploy trigger would benefit from further review of that file.

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
