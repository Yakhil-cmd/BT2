### Title
Signature verification is keyed on `repository.owner.login`, but the effect targets `repository.full_name` — cross-org write via forged webhook - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `lib/shipit.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC validation based on `repository.owner.login` (or `organization.login`), while every `Handler` subclass resolves the repository/stack to mutate from a *different* field of the same JSON body: `repository.full_name` [1](#0-0) [2](#0-1) [3](#0-2) . These two fields are never cross-checked against each other before the handler acts, so an org that legitimately signs a payload can point the `full_name` field at an entirely different, unrelated repository/stack that Shipit tracks.

### Finding Description
This mirrors the reported circuit bug's root cause: two logically-independent values (there, `address` and `shard_id`; here, "the org whose secret authenticated the request" and "the repository the payload claims to describe") are packed/derived from the same payload but consumed with mismatched binding, so a value never actually validated ends up driving the state transition.

- `verify_signature` computes `repository_owner` purely from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and uses it only to select the `GitHubApp` (and thus `webhook_secret`) used to validate `X-Hub-Signature`: [4](#0-3) 
- `Shipit.github(organization:)` maps an organization name to a per-org config (including its own `webhook_secret`), confirming that Shipit is designed to host multiple independent GitHub orgs, each with their own installation/secret: [5](#0-4) 
- Once the signature check passes, the *entire raw payload* — including whatever `repository.full_name` the attacker put in the body — is handed unmodified to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) .
- Every handler resolves the target `Stack`/`Commit` set via `repository_name = payload.dig('repository', 'full_name')`, with no re-validation that this repository actually belongs to the same organization whose secret unlocked the request: [3](#0-2) 
- Concrete handlers act directly on whatever stacks/commits that lookup returns, e.g. `PushHandler` triggers `stack.sync_github` for matching branches [7](#0-6) , and `StatusHandler` writes a commit status for any commit in the DB with a matching `sha` regardless of repository [8](#0-7) .

**Equality that should hold but doesn't:**
`org_that_signed(payload.repository.owner.login) == org_that_owns(payload.repository.full_name)`

Before the attacker's request: a webhook signed with Org B's `webhook_secret` can only legitimately describe Org B's repositories. After the attacker's crafted request: `repository.owner.login = "org-b"` (satisfies signature check against Org B's secret) while `repository.full_name = "org-a/target-repo"` (a completely different, unrelated repository/stack already tracked by Shipit under Org A). `verify_signature` only checks the former; every handler acts only on the latter.

### Impact Explanation
An attacker who has administrative control of one GitHub organization onboarded to this Shipit instance (and therefore legitimately knows/controls that org's `webhook_secret`, which is standard practice for org admins configuring a GitHub App/webhook) can forge signed webhook deliveries whose `repository.full_name` names a stack belonging to a *different* organization also tracked by the same Shipit instance. Depending on event type this allows:
- Forcing `GithubSyncJob`/`sync_github` on another org's stack via forged `push` events, causing Shipit to fetch and act on attacker-influenced ref state for a repository the attacker doesn't own.
- Forging `status`/`check_suite` events to fabricate CI/check results (`commit.create_status_from_github!`) for another org's commits — which can gate merge/deploy decisions (`deployable_status`, `merge_status` flows) — potentially leading to an unauthorized deploy for a repository the attacker has no legitimate access to.

This crosses the "cross-repository writes" / "unauthorized deploy" threshold called out in scope, since state belonging to Org A's stacks is mutated using authorization material that only ever proved control of Org B.

### Likelihood Explanation
Requires the attacker to control (or know the webhook secret of) at least one org already configured in this Shipit instance's `github:` block — a realistic scenario for any multi-tenant Shipit deployment serving several independent GitHub orgs, since setting up the GitHub App integration for one's own org is a normal, unprivileged (relative to *other* orgs) operation. No access to the target org, its repo, or its GitHub credentials is required — only a same-instance sibling org's secret and knowledge/guess of a target `owner/repo` name tracked by the same Shipit deployment.

### Recommendation
In `WebhooksController#verify_signature` (or immediately after it, before dispatch), assert that the organization used to select the verifying `webhook_secret` matches the actual owner of `repository.full_name` (i.e., re-derive/compare `repository.full_name.split('/').first` against `repository_owner`, or better, verify the signature using the config keyed by the repository's owner derived consistently from a single canonical field), rejecting the request with `422` on mismatch — analogous to how MatterLabs fixed `pack_key` by correcting the offset/coefficient so unrelated fields no longer bleed into each other, and adding an explicit assertion binding the two.

### Proof of Concept
1. Shipit is configured with two orgs, `org-a` and `org-b`, each with their own GitHub App/`webhook_secret` (per `config/secrets*.yml` schema) [9](#0-8) .
2. Attacker administers `org-b` and therefore knows `org-b`'s `webhook_secret`.
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-b" }, "full_name": "org-a/target-repo" }
}
```
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC(webhook_secret_org_b, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "org-b")` and successfully verifies the signature against `org-b`'s secret [1](#0-0) .
6. `PushHandler` resolves `repository_name` from `repository.full_name` = `"org-a/target-repo"` and enqueues `sync_github` for `org-a`'s stack [3](#0-2) [7](#0-6) , despite the request never being authenticated as coming from `org-a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
