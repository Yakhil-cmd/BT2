### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while handlers act on the unrelated `repository.full_name` / `sha` fields, letting a holder of one org's webhook secret write into another org's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify the HMAC against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) . The actual entity mutated by the event handlers, however, is derived from a *different* field of the same payload: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to look up the `Repository`/`Stack` to act on [2](#0-1) , and `StatusHandler#process` matches on the raw `sha` param against *any* `Commit` in the database, independent of the verified organization at all [3](#0-2) . Because the code never checks that the org used to select the webhook secret actually owns the `repository.full_name`/`sha` being acted upon, an attacker who legitimately controls a GitHub App installation on their own organization (and thus knows that org's `webhook_secret`) can forge a validly-signed webhook body whose `repository.owner.login` is their own org (to pass verification) but whose other fields (`repository.full_name`, `sha`, commit `state`) target a victim organization's stack.

### Finding Description
This mirrors the reported ERC4626 bug class: a check is performed against one identity (`msg.sender`/here, "the org whose secret validated the signature") while the state mutation is applied against a different identity (`owner`/here, "the repository or commit actually written"). The binding that should hold is:

`organization verified by HMAC == organization that owns the repository/stack being mutated`

but the code never enforces this equality. `verify_signature` only proves "this raw body was HMAC-signed with the secret configured for `repository_owner`" [4](#0-3) ; it never cross-checks that field against the `repository.full_name` field that `Handler#repository_name` subsequently uses to locate the target `Stack` [2](#0-1) . Since a Shipit deployment can host multiple GitHub organizations, each with its own `webhook_secret` (as documented and tested in `docs/setup.md` "Using Multiple Github Applications" and `lib/shipit.rb#github`) [5](#0-4) , an attacker who is a legitimate GitHub App admin/installer for their own org "attacker-org" possesses that org's `webhook_secret` and can freely compute a valid `X-Hub-Signature` over any JSON body of their choosing, including one where `repository.owner.login` = `"attacker-org"` but `repository.full_name` = `"victim-org/victim-repo"`.

Concretely:
- `PushHandler#process` resolves target stacks via `stacks` (i.e., `Handler#repository_name`, `payload.dig('repository','full_name')`) and calls `stack.sync_github(...)` on them, without any tie back to `repository_owner` [6](#0-5) .
- `StatusHandler#process` is even weaker: it matches purely on `params.sha` against `Commit.where(sha: ...)` globally, with no repository/org scoping check at all, and calls `commit.create_status_from_github!(params)`, injecting an attacker-controlled `state`/`description`/`target_url`/`context` [7](#0-6) . Newly-created `Status` records trigger `schedule_continuous_delivery` and `enable_ci_on_stack` callbacks [8](#0-7) , meaning a forged "success" status for a known commit SHA on a victim's continuous-deployment-enabled stack can trigger an unauthorized deploy.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" binding explicitly called out in scope. Concretely, an attacker with legitimate but low-privilege access to one GitHub org's App installation (their own) can forge webhook events that write fake CI status entries for arbitrary commit SHAs belonging to a victim stack in the same Shipit instance, and this can trigger continuous delivery to actually deploy that commit — an unauthorized deploy, which is explicitly listed as a Critical impact.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration), and (2) attacker control of a legitimate GitHub App installation for one of those orgs (i.e., knowledge of that org's `webhook_secret`, which any org admin installing the app would have). No repository write access to the victim's repo, no Shipit session, and no `ApiClient` token are required — only knowledge of the SHA of a commit already known to Shipit (visible on the public dashboard/API) for the victim stack.

### Recommendation
In `WebhooksController#verify_signature`, after selecting `github_app` by `repository_owner`, verify that the same organization name is consistent with `repository.full_name`'s owner portion (or equivalently, load the target `Repository`/`Stack` first and confirm its `owner` matches `repository_owner` before dispatching to handlers). Additionally, `StatusHandler` should scope `Commit.where(sha:)` lookups to commits belonging to a stack whose repository owner matches the verified `repository_owner`, rather than matching by SHA alone across the entire database.

### Proof of Concept
1. Attacker legitimately installs the Shipit-integrated GitHub App on `attacker-org` and thus knows `attacker-org`'s `webhook_secret` (configured under `secrets.github.attacker-org.webhook_secret`).
2. Attacker identifies a commit SHA already tracked by a victim's Shipit stack (`victim-org/victim-repo`), e.g. via the public Shipit dashboard.
3. Attacker crafts a JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, verifies successfully against `attacker-org`'s secret [9](#0-8) .
6. `StatusHandler#process` finds the victim's `Commit` by SHA (globally, no org check) and creates a forged `success` status on it [3](#0-2) , potentially triggering `schedule_continuous_delivery` and an unauthorized deploy on the victim's stack [10](#0-9) .

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

**File:** app/models/shipit/status.rb (L18-34)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```
