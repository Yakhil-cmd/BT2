### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, but handlers act on the repository named in `repository.full_name` from the same unsigned-selection payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization's `webhook_secret` to validate the inbound HMAC against by reading `repository.owner.login` (falling back to `organization.login`) straight from the attacker-supplied JSON body, before the signature has been checked. Once verification "passes" (including trivially, when that organization has no `webhook_secret` configured), every registered handler resolves the target `Stack`/`Repository` using a *different* field of the same payload: `repository.full_name` ` [1](#0-0) `. Nothing ties these two fields together, so the organization whose credentials/secret authorized the request is not necessarily the organization that owns the repository being acted upon.

### Finding Description
`verify_signature` computes the org used to select the secret purely from body content: [2](#0-1) 

`verify_webhook_signature` returns `true` unconditionally when the selected org has no `webhook_secret` configured: [3](#0-2) 

All handlers, however, resolve which `Repository`/`Stack` to mutate using `repository.full_name`, an independent field of the same JSON body: [4](#0-3) [5](#0-4) [6](#0-5) 

The binding that should hold is: `organization authenticated by verify_signature == organization that owns the repository written by the handler`. In a multi-org Shipit deployment (`config/secrets.*.yml` `github:` hash keyed by org, e.g. `test/dummy/config/secrets_double_github_app.yml`), this equality is never enforced. An attacker who can produce a signature valid for **any one** configured organization (trivial if that org has `webhook_secret: nil`, as several documented/example configs show, e.g. `config/secrets.development.example.yml:11`) can set `repository.owner.login`/`organization.login` to that weak org while setting `repository.full_name` to `"other-org/other-repo"`. `verify_signature` authenticates against the weak org's (absent) secret and passes; `StatusHandler`/`PushHandler`/etc. then look up and mutate the *other* org's `Repository`/`Stack` via `Repository.from_github_repo_name(params.repository.full_name)`.

Concretely, `StatusHandler#process` writes attacker-controlled CI `state`/`context`/`description` directly onto any existing `Commit` matching `params.sha` in the target stack via `Commit#create_status_from_github!`, with no further validation against GitHub. Shipit's CI-gating logic (`MergeRequest#reject_unless_mergeable!`, `StatusChecker`) and deploy safety checks consume these `Status` rows to decide whether a commit is "deployable" / a merge request's required checks have passed. A forged "success" status for an arbitrary commit sha therefore poisons the gating signal for a stack the attacker never had any relationship with, cheaply "bought" from a org boundary they do control (their own low-security org config) — directly analogous to the reported bug class where a value is priced/validated against the wrong internal reference and the mismatch is exploited to extract value that should have been protected by an external, unforgeable check.

### Impact Explanation
This breaks the organization-authenticates ⇔ repository-is-written binding required by the rules. Concretely it lets an attacker forge Status/CI events (and other repository/Stack-scoped webhook effects such as push-triggered `GithubSyncJob`, membership/team changes) for a Stack belonging to an organization they were never authenticated for, using only the (possibly absent) webhook secret of an unrelated, weaker org they control in the same Shipit deployment. Poisoned CI status can be consumed by merge-queue automation (`MergeRequest#reject_unless_mergeable!` / `all_status_checks_passed?`) that autonomously merges pull requests once required checks pass, enabling an effectively unauthorized merge without any Shipit session, API token, or webhook secret for the target organization/repository.

### Likelihood Explanation
Exploitability requires only: (1) a multi-organization Shipit deployment (explicitly supported and documented), and (2) at least one configured organization with no `webhook_secret` set (shown as valid/example configuration in `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`), or one whose secret the attacker otherwise knows. No GitHub App private key, `ApiClient` token, or Shipit session is needed — only the ability to POST to the public `/webhooks` endpoint. This is a realistic operational configuration, not a purely theoretical one.

### Recommendation
Bind the authenticated organization to the specific repository the handler is about to mutate: after `Shipit.github(organization: repository_owner)` verifies the signature, re-derive the acted-upon repository strictly from `repository.owner.login` (the same field used for verification), and reject/ignore the event if `repository.full_name`'s owner segment does not case-insensitively match `repository_owner`. Alternatively, verify the signature using the webhook secret of the organization that owns `repository.full_name` (not a separately-supplied `owner`/`organization` object), and require a non-blank `webhook_secret` for every configured organization so that a missing secret can never trivially authenticate arbitrary payloads.

### Proof of Concept
1. Deploy Shipit configured with two GitHub organizations, `weak-org` (no `webhook_secret` set) and `victim-org` (properly secured), each managing at least one `Repository`/`Stack` — a supported and documented configuration (`test/dummy/config/secrets_double_github_app.yml`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of an existing commit on a victim-org stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "weak-org" }, "full_name": "victim-org/victim-repo" }
}
```
No `X-Hub-Signature` header is needed (or any arbitrary value) because `weak-org` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally ` [3](#0-2) `.
3. `verify_signature` passes because it only checked `weak-org`'s (absent) secret ` [7](#0-6) `.
4. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — which resolves against `victim-org/victim-repo`'s commits — and writes a forged "success" status ` [8](#0-7) `, even though the request was never authenticated for `victim-org`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
    end
```
