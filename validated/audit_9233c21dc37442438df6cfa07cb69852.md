## Analysis

This confirms the analog to the "missing scalar field range check" bug class: a value used to select the trust/authentication context (`repository.owner.login`, used to pick which org's `webhook_secret` verifies the HMAC) is never cross-checked against the value the same payload later uses to determine *which repository is actually acted upon* (`repository.full_name`).

### Binding broken

`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC secret) using: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

where `repository_owner` reads `params.dig('repository','owner','login')`: [2](#0-1) 

That HMAC only proves *"the sender knows the webhook_secret belonging to organization X"*. It does **not** prove anything about the `repository.full_name` field that handlers later use to pick the target `Repository`/`Stack`: [3](#0-2) [4](#0-3) [5](#0-4) 

Both fields live in the same attacker-controlled JSON body; `verify_signature` reads one field (`repository.owner.login`) to select the secret while `PushHandler`/PR handlers/`Repository.from_github_repo_name` read a different field (`repository.full_name`) to determine what gets synced/archived/deployed. Nothing enforces `full_name.split('/').first == repository.owner.login`.

This is exactly the pattern called out as in-scope: **"an organization that authenticated versus the repository that is written."**

This deployment model is explicitly supported: `Shipit.github_app_config` / `Shipit.github` look up per-organization secrets from a multi-tenant `secrets.github` config keyed by org name, as documented in `docs/setup.md`'s "Using Multiple Github Applications" section, and implemented in: [6](#0-5) 

### Exploit path

1. Instance is configured (per documented multi-org setup) to track repos from `OrgA` and `OrgB`, each with its own GitHub App / `webhook_secret`.
2. An attacker who is only a member/admin of `OrgA` (no Shipit session, no `ApiClient` token, no access to `OrgB`) knows or can obtain `OrgA`'s `webhook_secret` (e.g. it is visible to anyone who can configure GitHub App webhooks for `OrgA`, or it can be leaked from any `OrgA` webhook delivery which is not IP/allow-list restricted).
3. Attacker POSTs directly to the public `/webhooks` endpoint (no authentication required by design) with a forged JSON payload where `repository.owner.login = "OrgA"` (so `Shipit.github(organization: "OrgA")` is used for verification) but `repository.full_name = "OrgB/target-repo"`.
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC(OrgA_webhook_secret, raw_body)` — this passes `verify_signature` because it only checks the secret tied to `OrgA`.
5. `WebhooksController#create` then dispatches to `Shipit::Webhooks.for_event(event)` handlers, e.g. `PushHandler#process`, which resolves the target via `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` — triggering GitHub sync/deploy activity against `OrgB`'s stack, an org the attacker never authenticated to.

### Uncertainty

I could not fully trace what `sync_github`/downstream deploy triggers do with an attacker-chosen `expected_head_sha` (e.g., whether it can force a deploy to an arbitrary attacker-controlled commit SHA on `OrgB`'s repo, versus merely triggering a legitimate GitHub API sync that would reject unknown SHAs). That downstream effect determines whether impact reaches "unauthorized deploy" (Critical/High) or is limited to spurious sync/job noise. This would need verification by reading `Stack#sync_github` and `GithubSyncJob`, which I was not able to inspect in this session.

### Title
Cross-organization webhook confusion via unbound `repository.owner.login` vs `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The webhook signature verification selects the HMAC secret based on `repository.owner.login`, but downstream event handlers act on the independently-attacker-controlled `repository.full_name` field from the same JSON body, with no cross-check binding the two.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to select which org's `webhook_secret` to verify the signature with [7](#0-6) . Every downstream handler instead trusts `payload.dig('repository','full_name')` to resolve the actual `Repository`/`Stack` to act on [3](#0-2) . On a multi-organization Shipit deployment (explicitly documented and supported via `Shipit.github_app_config` [8](#0-7) ), these two fields can be made inconsistent by an attacker who controls only one of the configured organizations.

### Impact Explanation
An attacker who administers one tenant organization on a shared Shipit instance can forge webhook deliveries that pass signature verification (using their own org's secret) yet cause the engine to run push/PR handlers against a different tenant's repository/stack, e.g. triggering `PushHandler`'s `stack.sync_github` calls [9](#0-8)  against `OrgB`'s stacks without ever authenticating as `OrgB`.

### Likelihood Explanation
Requires a multi-organization Shipit deployment and knowledge of one tenant's `webhook_secret` — a credential scoped to org-admin level rather than to a Shipit account, making it a plausible unprivileged-attacker path in this specific deployment pattern.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after verifying the signature, cross-check that `repository.full_name`'s owner segment matches the `repository_owner` (and, ideally, that the organization credentials used for verification match the one associated with the resolved `Shipit::Repository`) before dispatching to handlers.

### Proof of Concept
Not independently executed; derived from static review of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`, `app/models/shipit/repository.rb`, and `lib/shipit.rb` as cited above.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
