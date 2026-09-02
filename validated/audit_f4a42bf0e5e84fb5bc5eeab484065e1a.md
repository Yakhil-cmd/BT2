This confirms a real cross-organization trust binding break in the webhook signature verification.

### Title
`verify_signature` authenticates against `repository.owner`/`organization.login` while `Handler#stacks` resolves the target repository from `repository.full_name` — organization-key mismatch allows cross-repository event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from either `repository.owner.login` or, as a fallback, `organization.login` in the raw JSON payload. [1](#0-0)  The actual repository/stack that the event is applied to, however, is resolved independently in `Handlers::Handler#repository_name`/`#stacks` from `payload.dig('repository', 'full_name')`. [2](#0-1)  Because Shipit supports multi-organization GitHub App configuration where each organization has its own `webhook_secret` (`Shipit.github(organization:)` / `github_app_config`), [3](#0-2)  these two payload fields are never bound together by the signature check.

### Finding Description
The equality that should hold is: `organization whose webhook_secret authenticated the request == owner of the repository the event acts on`. In this engine that equality is never enforced. `repository_owner` (used to pick the HMAC secret) is derived from `repository.owner.login`, but can fall back to the top-level `organization.login` key if `repository` lacks an `owner` sub-object: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [4](#0-3)  Meanwhile every downstream handler (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, etc.) looks up the repository/stack purely from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`, with no re-check that `full_name`'s owner segment matches `repository_owner`. [2](#0-1) [5](#0-4) 

An attacker who controls (or has compromised) a GitHub App/webhook installation for organization `attacker-org` — and thus legitimately possesses `attacker-org`'s `webhook_secret` — can send a raw POST to `/webhooks` with `X-Hub-Signature` computed with `attacker-org`'s secret, while crafting the JSON body so that `organization.login` (or `repository.owner.login`) is `attacker-org` (so the signature check passes against the correct secret) but `repository.full_name` is `victim-org/victim-repo`. `verify_signature` will succeed because it authenticated the correct organization for the signature it received; but `PushHandler#stacks` will then operate on whatever stack is registered under `victim-org/victim-repo`, e.g. triggering `stack.sync_github(expected_head_sha: params.after)` for a repository the requester does not control. [6](#0-5) 

### Impact Explanation
This breaks the binding between "the organization whose credential authenticated the webhook" and "the repository being written to," which the rules classify as an unprivileged-attacker analog worth flagging. The concrete blast radius depends on handler semantics: `push` triggers a `GithubSyncJob`/`sync_github` for the target stack using attacker-chosen `after` SHA and `ref`, and `pull_request` events can archive/unarchive review stacks or update PR label state cross-organization — all without any credential for the victim organization. This does not reach RCE or `GITHUB_TOKEN` exfiltration directly, but it does allow cross-repository writes to another organization's Shipit stack state driven purely by a signature valid for a different, attacker-controlled organization.

### Likelihood Explanation
Requires the attacker to operate/control at least one organization/repository that is registered in the same Shipit instance (multi-tenant deployment using per-organization `github` config keys) — this is the normal deployment mode Shipit documents for shared installations. No other credential is required beyond the attacker's own legitimate webhook secret for their own org, which they already possess for their own registered repository. This satisfies the "unprivileged attacker" framing since the attacker only needs standing as a normal tenant, not privileged access to the victim org.

### Recommendation
In `WebhooksController#verify_signature`, and/or in `Webhooks::Handlers::Handler`, ensure the same repository owner used to select the verifying `webhook_secret` is the one used to resolve the target repository — i.e., derive `repository_owner` strictly from `repository.full_name`'s owner segment (or explicitly cross-check `repository.owner.login`/`organization.login` against `repository.full_name`'s owner before dispatching to handlers), rejecting the payload if they diverge.

### Proof of Concept
1. Attacker registers `attacker-org` as a Shipit organization/GitHub App with its own `webhook_secret` (a normal, unprivileged tenant setup).
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` over a crafted `push` payload body where the top-level `organization.login` (or `repository.owner.login`) is `attacker-org`, but `repository.full_name` is `victim-org/victim-repo` and `after` is an attacker-chosen SHA.
3. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, and the HMAC check passes because the attacker used the correct (their own) secret. [7](#0-6) 
4. `PushHandler#stacks` calls `Repository.from_github_repo_name('victim-org/victim-repo')` and, if that stack exists, invokes `stack.sync_github(expected_head_sha: <attacker-controlled after>)` — a write against `victim-org`'s stack triggered entirely by `attacker-org`'s credential. [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
