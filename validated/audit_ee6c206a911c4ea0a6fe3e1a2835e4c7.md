## Finding

### Title
Cross-organization webhook forgery via signature/repository binding mismatch in `WebhooksController` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate an inbound webhook against using an *attacker-controlled* field of the very payload it is about to trust (`repository.owner.login` / `organization.login`), while the handlers that subsequently act on that payload resolve the target repository/stack from a *different* field of the same payload (`repository.full_name`, or in the case of the `status` event, no repository scoping at all). In a multi-organization Shipit deployment, this breaks the equality "organization that authenticated == repository that is written," allowing anyone who knows the `webhook_secret` for **one** configured organization to forge webhook events that mutate stacks belonging to **any other** configured organization.

### Finding Description
`verify_signature` picks the signing secret like this: [1](#0-0) 

`repository_owner` is read straight out of the unauthenticated JSON body: [2](#0-1) 

`Shipit.github(organization:)` looks up a **per-organization** app config (own `webhook_secret`) in multi-app installations: [3](#0-2) 

The example multi-org secrets schema shows each org has its own independent `webhook_secret`: [4](#0-3) 

However, once the signature check passes, handlers resolve the *actual target repository* from a **separate, unrelated field** of the same body — `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

`PushHandler` uses that `stacks` helper directly to trigger a resync: [6](#0-5) 

Worse, `StatusHandler` performs **no repository scoping whatsoever** — it matches on `sha` alone, globally across every stack in the installation: [7](#0-6) 

Because the HMAC-SHA1 signature only proves "this exact byte string was signed with organization X's secret," and X is itself read from an attacker-editable field inside that byte string, an attacker who is a legitimate collaborator on (or otherwise possesses the webhook secret for) *one* org configured in Shipit can set `repository.owner.login` to their own org (so verification succeeds with a secret they know) while setting `repository.full_name` to a victim org/repo, or simply target any known commit `sha` via a `status` event with no owner field constraint on the affected data at all.

### Impact Explanation
This crosses the "organization that authenticated vs. repository that is written" trust boundary explicitly called out as in-scope:
- `push`/`check_suite` events: an attacker can force `GithubSyncJob`/`RefreshCheckRunsJob` to run against a victim stack, and — because `expected_head_sha` is attacker-supplied — can influence sync/continuous-delivery timing for stacks in an org the attacker does not control, potentially triggering an unauthorized/earlier deploy on `continuous_delivery`-enabled stacks.
- `status` events: since `StatusHandler` has no repository binding at all, an attacker holding *any* one org's webhook secret can write a fabricated commit status (e.g., forging a passing CI status) onto any commit `sha` tracked anywhere in the Shipit instance, which can be used to satisfy release-status/CI gating checks (`release_status_context`) that gate deploy eligibility — i.e., an unauthorized deploy path.

Both are cross-repository/cross-organization writes achieved purely from a payload-controlled routing decision, meeting the "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Exploitation requires only knowledge of a valid `webhook_secret` for *any one* organization configured in the Shipit instance (a normal outside collaborator/admin of that org's GitHub App settings would have this), plus knowledge of a target commit `sha` or repository `full_name` for the victim org, both of which are public/observable via the target org's own GitHub activity. No access to Shipit itself, no `ApiClient` token, and no compromise of the victim org's secret is required — only multi-org deployments are affected, but this is a documented, supported configuration (`secrets_double_github_app.yml`, `config/secrets.development.example.yml`).

### Recommendation
Bind signature verification to the same identity used for routing:
- Verify the signature using the secret for the organization actually owning `repository.full_name` (derive the lookup organization from the same field the handlers use), not from a second, independently-editable field of the payload.
- Additionally scope `StatusHandler` (and any other handler lacking one) to the repository resolved for the request, instead of matching commits globally by `sha`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-accessible, webhook secret `secretA` known to attacker) and `OrgB` (victim, secret unknown to attacker), both with tracked stacks.
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<sha of a commit already tracked under OrgB/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(secretA, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `secretA`, and verification succeeds (attacker legitimately knows this secret).
5. `Shipit::Webhooks.for_event('status')` invokes `StatusHandler`, which finds `Commit.where(sha: params.sha)` — matching the victim commit under `OrgB` regardless of the `repository` field used for verification — and creates a forged, attacker-controlled status on it via `commit.create_status_from_github!(params)`. [8](#0-7)

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
