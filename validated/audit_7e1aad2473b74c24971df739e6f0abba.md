## Title
Webhook signature verification authenticates the wrong GitHub organization, allowing cross-repository webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, while every `Webhooks::Handlers::Handler` subclass resolves the `Stack`/`Repository` it acts on from a **different** field of that same unverified body: `repository.full_name`. Because these two fields are independently attacker-controlled in the raw POST body and are never checked for consistency, an attacker who controls (or has push/webhook access to) any organization onboarded to the Shipit instance can sign a forged payload with their own organization's valid webhook secret while pointing `repository.full_name` at a completely different, victim organization's repository. The signature check passes (it only ever validates the attacker's own org), but the resulting handler acts on the victim's stack.

### Finding Description
Signature selection and verification:
```ruby
# app/controllers/shipit/webhooks_controller.rb:24-30
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```
```ruby
# app/controllers/shipit/webhooks_controller.rb:59-62
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

Every handler, however, resolves the target repository/stacks from an entirely different path in the same JSON body:
```ruby
# app/models/shipit/webhooks/handlers/handler.rb:32-38
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

For example `PushHandler#process` triggers `stack.sync_github` for every stack matching `repository_name`/branch:
```ruby
# app/models/shipit/webhooks/handlers/push_handler.rb:12-17
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

The controller's own comment ("Fallback to the organization sub-object **if repository isn't included** in the payload") shows the intent was that `repository.owner.login` and `repository.full_name` always refer to the same repository — an assumption that only holds for genuine GitHub-generated payloads. Since the controller parses `request.raw_post` itself (`params = JSON.parse(request.raw_post)` in `create`, `app/controllers/shipit/webhooks_controller.rb:11`) and the signature only proves "this byte stream was HMAC-signed by organization X's secret," it proves nothing about which repository the *body's* `full_name` field claims to represent. This is the same class of bug as the reported one: a value used to decide "is this trusted?" (the last-bottle stake update boundary / here, the signing organization) is not the same value later consumed by business logic (the redeemed bottle / here, the acted-upon repository), so a crafted input that satisfies the check on one field silently drives behavior on the other, unchecked field. [5](#0-4) 

This is a concrete instance of the "organization that authenticated versus the repository that is written" trust binding: `verify_signature` authenticates `repository.owner.login`, but the handler writes/acts on `repository.full_name`.

### Impact Explanation
Any organization owner/admin that has legitimately onboarded their own org+repo to a shared Shipit instance (a routine, unprivileged-relative-to-other-tenants scenario for a multi-tenant Shipit deployment) can forge webhooks that are attributed to their own org's signature but target another tenant's repository/stack. Handlers that read `repository.full_name` to find stacks/commits include not just `PushHandler` (forces a resync) but also the `status` handler that writes `Status` records for a commit (confirmed by `WebhooksControllerTest#":state create a Status for the specific commit"`), which feeds directly into `merge.require`/CI-gating logic used to authorize merges via the merge queue. An attacker can therefore inject fabricated "success" CI/commit statuses onto a victim stack's commits, using only their own organization's webhook secret, to unblock or trigger unauthorized merges — matching the "unauthorized deploy, rollback or merge" / cross-repository writes impact class. [6](#0-5) 

### Likelihood Explanation
Exploitation requires no Shipit session, API token, or GitHub App private key — only the ability to receive/replay a legitimately signed webhook from any organization already configured in `Shipit.github_configuration` (e.g., the attacker's own org, which they administer). The attacker crafts the raw JSON body by hand (not a real GitHub-delivered payload) and computes the HMAC themselves with their own known secret, then POSTs it to the shared `/webhooks` endpoint. No other validation ties `repository.owner.login` to `repository.full_name`.

### Recommendation
In `verify_signature` (and in every `Handler` subclass), derive the organization used for both signature selection and for stack/repository resolution from a single, consistent field (e.g., always take the owner from `repository.full_name`, or explicitly validate that `repository.owner.login` matches the owner segment of `repository.full_name` before proceeding). Reject the webhook if these disagree.

### Proof of Concept
1. Attacker organization `attacker-org` is configured in Shipit with `webhook_secret = S`.
2. Attacker crafts a raw JSON body for a `status` (or `push`) event:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "branches": [{ "name": "master" }]
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` (they know `S`).
4. POST to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against `S` (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `StatusHandler` (via `Handler#repository_name` → `payload.dig('repository','full_name')`) resolves stacks for `victim-org/victim-repo` and writes a forged `Status` on the victim's commit, despite the request never being authenticated for `victim-org` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`). [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
