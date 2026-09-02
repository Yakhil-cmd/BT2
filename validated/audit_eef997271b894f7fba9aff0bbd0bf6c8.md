### Title
Webhook signature verification keyed by attacker-controlled `repository.owner.login` allows cross-organization/repository forgery when any configured GitHub org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App configuration (and thus which `webhook_secret`) to validate a webhook against using a field taken directly from the untrusted JSON body — `repository_owner` — while the handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field of that same untrusted body, `repository.full_name`. Because these two fields are never checked for consistency, and because `verify_webhook_signature` trivially returns `true` when the selected org's `webhook_secret` is blank, an attacker can pick any organization configured on the Shipit instance that has no `webhook_secret` set and use its login as `repository.owner.login`/`organization.login` to bypass signature verification entirely, while pointing `repository.full_name` at a completely different (properly secured) org/repo whose stacks then get processed as if the event were authentic.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

The org used to select the signing secret (`repository_owner`) comes straight from the JSON body the attacker fully controls (before any signature has been checked). `lib/shipit/github_app.rb#verify_webhook_signature` trivially passes when that org's `webhook_secret` is not configured:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Once `verify_signature` passes, `create` dispatches the *entire* raw payload to every handler registered for the event:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Handlers, however, never re-use `repository_owner`; instead they resolve the affected `Repository`/`Stack` from a separate field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`PushHandler`, for example, syncs every not-archived stack matching the branch of the referenced repo, using an attacker-suppliable `after` SHA:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

The equality this breaks is: **the organization whose credentials authenticated the webhook** (`repository_owner`, used to pick `webhook_secret`) **must equal the organization/repository whose state is actually written** (`repository.full_name`, used by handlers to select stacks). Nothing in the controller enforces this. A Shipit deployment that hosts multiple GitHub orgs (this is an explicitly supported configuration — see the two-org fixture `test/dummy/config/secrets_double_github_app.yml`, `OrgOne`/`OrgTwo`) can have one org intentionally left with `webhook_secret: nil` (e.g. a low-risk/testing org) while another org's repos are stacks with real deploy/merge automation. An attacker who knows or guesses the low-risk org's login can forge a payload:
```json
{
  "repository": { "owner": { "login": "low-risk-org-with-no-secret" }, "full_name": "high-value-org/critical-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>"
}
```
`verify_signature` looks up `Shipit.github(organization: "low-risk-org-with-no-secret")`, finds no `webhook_secret`, and returns `true` unconditionally — no HMAC is checked at all for this request. The payload is then dispatched to `PushHandler`, which resolves stacks via `repository.full_name = "high-value-org/critical-repo"` and calls `stack.sync_github(expected_head_sha:)` for that stack, completely independent of the (bypassed) org used for authentication.

### Impact Explanation
This crosses the binding this scan is meant to catch: "an organization that authenticated versus the repository that is written." An unauthenticated, unprivileged network attacker who can reach the public webhooks endpoint can inject forged GitHub events (push, status, pull_request, check_suite, membership, etc. — any handler resolving repo/stack via `repository.full_name`) targeting stacks belonging to an entirely different, properly-secured GitHub organization, as long as any other org configured on the instance lacks a `webhook_secret`. Depending on the handler this can force `GithubSyncJob`/`sync_github` calls that update tracked commits/branches for the target stack with attacker-chosen SHAs, or forge `status`/`check_suite` events affecting merge-queue and CI gating logic for that repo — enabling an unauthorized deploy/merge path against a repository the attacker was never authenticated for. This satisfies the "unauthorized deploy, rollback, or merge" high/critical impact bar.

### Likelihood Explanation
This does not require any credential, `ApiClient` token, `webhook_secret`, GitHub App private key, or any privileged access — it only requires knowledge that the target Shipit instance hosts more than one GitHub org and that at least one configured org has no `webhook_secret` set (a supported, documented configuration per `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, both of which show orgs with `webhook_secret: # nil`). This is a realistic operational configuration (e.g., internal/staging orgs configured without webhook secrets) and requires only crafting a plain HTTP POST with attacker-controlled JSON.

### Recommendation
Do not let an untrusted, unverified field of the payload select the trust context used to verify the payload. Verify the signature using the organization owning the actual target repository (`repository.full_name`'s owner) rather than a value the attacker also controls independently; alternatively, after signature verification succeeds for `repository_owner`, require that `repository_owner` matches the owner segment of `repository.full_name` before dispatching to handlers, and reject (422) on mismatch. Also reconsider making `verify_webhook_signature` return `true` whenever `webhook_secret` is blank — this creates an "always trusted" org for any deployment, which combined with the split-field lookup is the root of the crossing.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, e.g. `OrgLow` (no `webhook_secret`) and `OrgHigh` (with `webhook_secret` set and a tracked stack `OrgHigh/critical-repo` on branch `main`).
2. As an unauthenticated attacker, POST to the webhooks endpoint:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": { "owner": { "login": "OrgLow" }, "full_name": "OrgHigh/critical-repo" }
}
```
3. `verify_signature` computes `repository_owner = "OrgLow"`, loads `Shipit.github(organization: "OrgLow")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the (garbage) `X-Hub-Signature` header.
4. `create` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("OrgHigh/critical-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` for `OrgHigh`'s stack — a write against `OrgHigh` triggered without ever validating a signature scoped to `OrgHigh`. [7](#0-6) [3](#0-2) [8](#0-7) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-42)
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
end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
