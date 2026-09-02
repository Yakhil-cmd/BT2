### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while every event handler trusts the unrelated `repository.full_name` field, letting a webhook signed by one tenant's GitHub App forge events for another tenant's repositories - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC validation based on `repository.owner.login` (falling back to `organization.login`), but never checks that the same field agrees with `repository.full_name`, which is the field every `Webhooks::Handlers::Handler` subclass actually trusts to resolve the target `Repository`/`Stack`. Because Shipit supports multiple GitHub organizations/Apps in one instance (`Shipit.github(organization: ...)`, `config/secrets*.yml` allow several org entries), the field used to select the signing secret and the field used to select the acted-upon repository are decoupled inside the same signed payload, breaking the intended binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes the org used for signature verification purely from attacker-controlled JSON body content: [1](#0-0) [2](#0-1) 

The HMAC covers the raw body (`request.raw_post`), so the whole payload is "signed" - but only with respect to whichever organization's secret the attacker chooses via `repository.owner.login`. If the attacker legitimately controls a GitHub App/org tenant configured in Shipit (a normal, less-privileged multi-tenant setup, cf. `test/dummy/config/secrets_double_github_app.yml` showing multiple orgs sharing one Shipit instance), they know that org's `webhook_secret` and can freely construct any JSON body and sign it correctly for that org.

Every handler, however, resolves the target repository/stack from a *different* field, `repository.full_name`, not from `repository.owner.login`: [3](#0-2) 

For example `PushHandler` looks up stacks purely via `repository.full_name` and triggers a GitHub sync/deploy: [4](#0-3) 

`StatusHandler` creates a commit status purely keyed off `sha`, independent of which org's secret validated the request: [5](#0-4) 

`CheckSuiteHandler` similarly schedules a check-run refresh keyed on `stacks` (again resolved from `repository.full_name`) and `head_sha`: [6](#0-5) 

`Repository.from_github_repo_name` performs no cross-check against the org that authenticated the request: [7](#0-6) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_webhook_signature (repository.owner.login / organization.login)` == `repository written to by the handler (repository.full_name)`

Before the attack: these two fields are supposed to always refer to the same GitHub repository, because in a genuine GitHub-delivered webhook they come from the same event object.
After the attack: an attacker who owns/administers a legitimate, but different, GitHub App tenant (OrgA) crafts a raw JSON body where `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against OrgA's known `webhook_secret`) while `repository.full_name = "OrgB/victim-repo"` (a repository/stack belonging to a completely different, victim organization tracked by the same Shipit instance). The signature check passes (it's a valid HMAC for OrgA), yet the handler acts on OrgB's stack.

### Impact Explanation
This crosses a tenant/authentication boundary inside a single Shipit deployment that manages multiple GitHub organizations (a documented, supported configuration - see `docs/setup.md`/`secrets_double_github_app.yml` multi-org examples). Concrete consequences:
- Forge a `push` event for a victim stack to force `GithubSyncJob`/`stack.sync_github` against an arbitrary `expected_head_sha` under the attacker's control claim, potentially disturbing sync state or triggering re-evaluation of deploy state for a repository the attacker has no GitHub permissions on.
- Forge a `status` event to write a fabricated commit status (e.g., `state: success`, arbitrary `context`) for any commit SHA tracked by the victim's stacks, which can influence `ci.require` checks in `shipit.yml` and continuous-deployment logic (`ContinuousDeliveryJob#perform` gates on `stack.continuous_deployment?` and commit "deployable" state derived from statuses), potentially causing an unauthorized/incorrect deploy decision on the victim's stack.
- Forge a `check_suite` event to schedule check-run refresh for arbitrary victim commits.

This matches the report's "impact must be one of ... an unauthorized deploy" bar: forging CI/status signals used to gate `ContinuousDeliveryJob`'s trigger of `stack.trigger_continuous_delivery` is a direct path toward an unauthorized deploy of a repository the attacker does not control on GitHub.

### Likelihood Explanation
Requires the attacker to control (own/administer) at least one legitimate GitHub App tenant configured on the same shared Shipit instance - i.e., know that tenant's `webhook_secret`. This is a normal, documented multi-org configuration for Shipit (not a privileged internal secret), so any org onboarded to a shared Shipit instance is effectively "unprivileged" with respect to other orgs' repositories, yet this bug lets it forge events for them. No GitHub write access, no Shipit session/API token, and no interception of the victim's secret is required - only knowledge of the attacker's own org's webhook secret and the ability to POST directly to `/webhooks`.

### Recommendation
Bind the value used to select/verify the signature to the same value handlers act on. Concretely:
- Verify the webhook signature using the organization derived consistently from `repository.full_name`'s owner (or verify against all configured orgs and require that the org that validated equals the owner in `repository.full_name`), not a separately-dug `repository.owner.login`/`organization.login`.
- In `Shipit::Webhooks::Handlers::Handler`, cross-check that the repository resolved from `payload['repository']['full_name']` belongs to the same organization that was used in `WebhooksController#verify_signature`, rejecting the event otherwise.

### Proof of Concept
1. Attacker administers GitHub App/org `OrgA`, which is configured as a tenant in the shared Shipit instance and knows `webhook_secret` for `OrgA` (`Shipit.github(organization: "OrgA").verify_webhook_signature`).
2. Shipit also hosts stacks for a victim org/repo `OrgB/victim-repo` (different tenant, same Shipit instance) - see multi-org config pattern in `test/dummy/config/secrets_double_github_app.yml`.
3. Attacker builds a raw JSON body:
```json
{
  "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "branches": [{"name": "main"}]
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and the signature validates successfully (it was signed with OrgA's real secret).
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which ignores `repository.owner.login` entirely and, via `Commit.where(sha: params.sha)`, creates a forged "success" status on the victim commit belonging to `OrgB/victim-repo`, even though the attacker has no relationship whatsoever with `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
      end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-18)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
      end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
