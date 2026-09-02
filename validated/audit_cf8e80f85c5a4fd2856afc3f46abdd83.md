### Title
Cross-tenant webhook forgery: `repository.owner.login` used for signature verification never matches `repository.full_name` used by handlers, allowing org A's webhook secret to mutate org C's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App (and its `webhook_secret`) using `repository.owner.login` from the JSON body, while every event `Handler` (via `Handler#repository_name`/`Handler#stacks`) resolves the target `Repository`/`Stack` using the independent `repository.full_name` field from the same body. Because the attacker fully controls the raw POST body they sign, these two fields can be set to different organizations, letting an attacker who owns org A's real `webhook_secret` forge a signed request that is verified as belonging to A but is processed by handlers against org C's stacks/commits.

### Finding Description
The broken binding, stated as an equality that the code never checks:
`repository_owner` (used in `verify_signature`, from `params.dig('repository','owner','login')`) MUST equal the owner segment of `payload.dig('repository','full_name')` (used in `Handler#stacks`) for the verification to actually authorize the object being mutated. This is never asserted.

Code path:
- `Shipit::WebhooksController#verify_signature` picks the app config via `repository_owner` and does `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, request.raw_post)`. [1](#0-0) 
- `repository_owner` is read from `repository.owner.login` (or fallback `organization.login`), a JSON field fully controlled by whoever crafts the POST body. [2](#0-1) 
- After verification, `WebhooksController#create` dispatches the **same raw params** to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 
- Every handler's base class resolves the target repository/stack from a **different** field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 
- `PushHandler#process` and `CheckSuiteHandler#process` both operate on `stacks` derived from that unchecked `full_name`, calling `stack.sync_github` and `commit.schedule_refresh_check_runs!` respectively. [5](#0-4) [6](#0-5) 

Root cause: no code between `verify_signature` and any handler's `.call` asserts `repository.full_name.split('/').first == repository_owner`. `Repository.from_github_repo_name` simply does `find_by(owner:, name:)` from the untrusted `full_name` string with no relation back to the verified organization. [7](#0-6) 

Attacker's exact request: attacker legitimately controls org A's GitHub App installation (and thus its real `webhook_secret`, e.g. by owning a repo under org A that is onboarded to the same Shipit instance as org C). They send `POST /webhooks` with header `X-Github-Event: push` (or `check_suite`, or any `pull_request` event), body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "A" },
    "full_name": "C/some-repo"
  }
}
```
signed with `HMAC-SHA1(A_webhook_secret, raw_body)` in `X-Hub-Signature`. `verify_signature` looks up org A's app, verifies successfully, and the same payload is handed to `PushHandler`, which resolves stacks for `C/some-repo` and calls `stack.sync_github(expected_head_sha: ...)` on a stack the attacker never authenticated for.

Existing guards (`ExplicitParameters` schema, `drop_unhandled_event`, `force_github_authentication`, `Repository` validations) do not close this: `ExplicitParameters` only validates field *types/presence*, not cross-field consistency; `Repository` validations constrain the *format* of `owner`/`name` but do not compare them against the request's verified organization; there is no session/API-client authorization involved at all in this path, since `/webhooks` is unauthenticated by design and relies solely on HMAC verification, which is bound to the wrong field.

### Impact Explanation
An attacker holding a legitimate GitHub App webhook secret for one tenant organization (A) hosted on a shared Shipit instance can forge signed webhook requests that are processed against a sibling tenant's (C) repositories/stacks/commits. Concretely, they can force `Stack#sync_github` to run for C's stack, force check-run refresh jobs to be scheduled against C's commits, and (via `pull_request/*` handlers, which use the same `Handler#repository_name`) manipulate review-stack provisioning/labels/state for C's pull requests — all without ever possessing C's secrets. This is a payload for one repository mutating another's stack/commit, matching the Critical severity category explicitly listed ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: the Shipit instance must be multi-tenant, i.e., `Shipit.github_apps` configured with more than one organization (documented/supported feature), and the attacker must legitimately control at least one onboarded organization's GitHub App/webhook secret (e.g., by being an org admin, or by owning a small/test org that some victim onboarded alongside their real org on the same Shipit deployment). This is a realistic scenario for shared/internal Shipit deployments serving multiple teams/orgs. Attacker cost is low: only a valid HMAC secret for any one tenant is needed, and the forged request is trivially repeatable against any other tenant's `full_name` strings (which are typically guessable/public GitHub repo names).

### Recommendation
In `Shipit::WebhooksController`/`Handler`, after successful signature verification, assert that the owning organization used for verification equals the owner encoded in `repository.full_name` (and any other repository/organization identifiers in the payload) before dispatching to handlers, e.g. reject the request if `payload.dig('repository','full_name')&.split('/')&.first&.downcase != repository_owner&.downcase`. Alternatively, have handlers scope stack/repository lookups by the already-verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure `Shipit.github_apps` with two orgs, `A` and `C`, each with a distinct `webhook_secret`, each with a real `Stack` (`stack_a` for `A/repo`, `stack_c` for `C/repo`) with matching `branch`.
2. For each of `push`, `check_suite`, `status`, `membership`, and each `pull_request/*` handler:
   - Build a payload whose `repository.owner.login == "A"` and `repository.full_name == "C/repo"` (and for `membership`, since it uses `organization.login` directly rather than `repository`, confirm it is *not* exploitable this way — showing the divergence is specific to handlers keyed off `repository.full_name`).
   - Sign the raw JSON body with `A`'s `webhook_secret`.
   - `POST /webhooks` with `X-Hub-Signature` and `X-Github-Event` set accordingly.
   - Assert response is `200 OK` (verification passed as A).
   - Assert that `stack_c` (org C's stack/commit) was mutated (e.g., `sync_github` called, `schedule_refresh_check_runs!` enqueued, PR state changed) despite the request only ever proving possession of `A`'s secret — i.e., assert the equality `full_name.split('/').first == repository_owner` is false yet the mutation still occurred, proving the missing check. [8](#0-7) [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-41)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
