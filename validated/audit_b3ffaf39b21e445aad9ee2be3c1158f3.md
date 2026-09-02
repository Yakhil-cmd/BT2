### Title
Webhook signature is verified against `repository.owner.login` while the write target is resolved from `repository.full_name` — cross-organization write via a mismatched multi-tenant webhook payload - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
In Shipit's multi-tenant GitHub App mode, the webhook signature check authenticates a payload against the secret of the organization named in `repository.owner.login` (or `organization.login`), but the handlers that actually mutate state resolve the target `Repository`/`Stack` from the independent `repository.full_name` field. These two fields are never cross-validated to be consistent, so the binding "organization whose secret authenticated the request" ≠ "repository that gets written to" can be broken by any payload where they disagree.

### Finding Description
`WebhooksController#verify_signature` selects which organization's webhook secret to verify against using only the repository owner (or organization) login pulled out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a *different* `GitHubApp` (and thus a different `webhook_secret`) per organization when the multi-org config schema is used: [3](#0-2) 

Once `verify_webhook_signature` returns true for the org derived from `repository.owner.login`, `create` dispatches the *entire raw payload* (including `repository.full_name`) to handlers: [4](#0-3) 

Every handler resolves the repository/stack to act on from `repository.full_name`, a field distinct from — and never cross-checked against — the `repository.owner.login` field used for signature selection: [5](#0-4) [6](#0-5) [7](#0-6) 

`repository.owner.login` and the owner-portion of `repository.full_name` are two separate keys in the same JSON object. Nothing in `verify_signature`, `PushHandler`, or `Handler#repository_name` enforces that they refer to the same organization. This is the same structural bug class as the PoolTogether finding: a check is performed on one derived value (`repository_owner` / `largestTierClaimed`), while the actual state-changing action is driven by a different, uncovered value (`repository.full_name` / `_nextNumberOfTiers`) that the check does not fully gate.

### Impact Explanation
If a Shipit deployment is configured with multiple GitHub organizations (multi-tenant `secrets.github` schema, each with its own `webhook_secret`, `app_id`, `installation_id`), an entity that legitimately controls or has compromised **one** tenant organization's webhook secret can craft a payload whose `repository.owner.login`/`organization.login` names that tenant (so the signature check passes) while `repository.full_name` names a repository belonging to a **different**, unrelated tenant organization onboarded to the same Shipit instance. Handlers such as `PushHandler` (`stack.sync_github(expected_head_sha: params.after)`), `CheckSuiteHandler`, `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler` (auto-provisioning/archiving review stacks, updating PR state) will then act on the victim organization's stacks — an unauthorized cross-repository write/state change performed under a signature that was never actually issued by, or verified against, that victim organization. This matches the "cross-repository writes" / "unauthorized deploy" impact class (e.g. `sync_github` can trigger a `GithubSyncJob` that updates deployed refs and can feed into continuous deployment for a repository the attacker's org has no legitimate relationship to).

### Likelihood Explanation
This requires the Shipit instance to be configured in the multi-organization GitHub App mode (`github_default_organization` non-nil, multiple orgs each with a `webhook_secret`) and requires the attacker to already possess (or have compromised) the webhook secret of at least one onboarded organization — they do not need any secret belonging to the victim organization, GitHub App install access to the victim repo, or a Shipit session/API token. Given that this is the documented multi-tenant deployment mode of the engine and webhook secrets are the only binding checked, likelihood is moderate: it is not exploitable by a fully anonymous attacker, but it crosses a trust boundary the design intends to keep separate (per-organization isolation of webhook authority), which is exactly the boundary GitHub Apps are meant to enforce.

### Recommendation
In `WebhooksController#verify_signature`, after establishing which organization's secret verified the signature, assert that the same organization matches every organization-identifying field used downstream (`repository.full_name`'s owner segment, `organization.login`), rejecting the request with 422 on mismatch. Alternatively, thread the authenticated organization through to `Shipit::Webhooks::Handlers::Handler` and have `repository_name`/`stacks` refuse to resolve a `Repository` whose `owner` differs from the organization that authenticated the webhook.

### Proof of Concept
1. Configure Shipit with two GitHub App tenants, `org-a` (attacker-controlled webhook secret) and `org-b` (victim), both with repositories tracked as Shipit stacks.
2. Attacker sends a `push` webhook to `/webhooks` with headers `X-Github-Event: push` and `X-Hub-Signature` computed using `org-a`'s `webhook_secret` over the raw body.
3. Body sets `repository.owner.login = "org-a"` (so `repository_owner` in `WebhooksController` resolves to `org-a`, and `verify_webhook_signature` succeeds using `org-a`'s secret) but sets `repository.full_name = "org-b/victim-repo"` and `ref`/`after` pointing at a commit the attacker wants deployed/synced.
4. `verify_signature` passes; `PushHandler#process` calls `Repository.from_github_repo_name("org-b/victim-repo")`, finds `org-b`'s stacks, and calls `stack.sync_github(expected_head_sha: params.after)`, causing Shipit to sync/act on `org-b`'s repository despite the request never being signed by `org-b`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
