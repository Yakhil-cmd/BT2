Based on my investigation, I found a concrete cross-organization/cross-repository trust-binding break in the inbound webhook signature verification path.

### Title
Webhook signature verified against attacker's organization secret while handlers act on an attacker-chosen repository from the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the untrusted JSON body itself, then simply checks that the signature is a valid HMAC for the raw payload under that organization's secret. Every event handler downstream, however, determines the actual repository/stack to write to using a *different* field of the same payload: `repository.full_name` (via `Shipit::Webhooks::Handlers::Handler#repository_name`). Nothing ties these two independently attacker-controlled fields together.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` from the request body (`params.dig('repository','owner','login') || params.dig('organization','login')`, see [2](#0-1) ) and fetches `Shipit.github(organization: repository_owner)` to obtain that organization's registered `webhook_secret`, then verifies the raw body's HMAC against it via `verify_webhook_signature` in [3](#0-2) .

Because Shipit supports multiple GitHub organizations each with its own `webhook_secret` (raising `Shipit::GithubOrganizationUnknown` for unregistered orgs), an attacker who controls (or is granted webhook delivery for) their own onboarded organization `attacker-org` possesses a legitimate `webhook_secret` for that org and can compute valid signatures for arbitrary JSON bodies.

Every dispatched handler, however, resolves the target repository independently from `repository.full_name`, e.g. `Handler#repository_name` in [4](#0-3) , used by `PushHandler` in [5](#0-4)  and by the status handler that writes `Status` records directly from payload fields, as shown in the test asserting the handler copies `state`, `target_url`, `description`, and `created_at` verbatim from the payload onto `commit.statuses` in [6](#0-5) .

The binding that should hold is:
`organization used to select/verify the webhook secret == organization that owns the repository the handler mutates`

but the code only enforces:
`signature valid for repository_owner's secret` while independently trusting `repository.full_name` for the write target — an equality that is never checked.

### Impact Explanation
An attacker who has a legitimately configured (even low-privilege) organization in Shipit's multi-tenant `github` app config can forge a webhook whose `repository.owner.login`/`organization.login` is set to their own org (so the HMAC verifies with their own secret) while `repository.full_name` (and, for the `status` event, `sha`, `state`, `description`, `target_url`) point at a **victim repository/commit they do not control**. This lets the attacker:
- Inject arbitrary CI/commit statuses (e.g. force `state: "success"`) onto any tracked commit in any onboarded repository, which is used by `release_status?`/`deployable?` gating in `Stack`/`DeploySpec` to authorize continuous deployment or manual deploys — i.e., an unauthorized deploy trigger via forged CI green light.
- Force `GithubSyncJob`/push processing on stacks belonging to repositories they don't own.

This meets the "unauthorized deploy" impact tier defined in scope.

### Likelihood Explanation
Exploitation requires only that the attacker controls or has delivery access to one legitimately onboarded GitHub organization/webhook secret in the Shipit instance (a realistic multi-tenant scenario, not a privileged Shipit account, API token, or the victim's own secret). No cross-repository or cross-organization correlation is performed anywhere in the verification path, so the attack is a single crafted HTTP POST to `/webhooks` with a correctly computed `X-Hub-Signature` for the attacker's own secret.

### Recommendation
After signature verification, cross-check that the organization used to select the webhook secret (`repository_owner`) matches the owner segment of `repository.full_name` (and, transitively, that the resolved `Repository`'s stored `owner` matches), rejecting the event (422) on mismatch before dispatching to any handler.

### Proof of Concept
1. Register/organization `attacker-org` in Shipit with its own `webhook_secret` (`S_a`), as a normal onboarded tenant.
2. Craft a `status` (or `push`) webhook JSON body:
```json
{
  "sha": "<victim commit sha tracked by Shipit>",
  "state": "success",
  "description": "forced green",
  "target_url": "https://attacker.example/",
  "created_at": "...",
  "repository": {
     "full_name": "victim-org/victim-repo",
     "owner": { "login": "attacker-org" }
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC(S_a, body)` using the attacker's own legitimate secret `S_a`.
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s secret, and the signature verifies successfully.
5. The status handler writes a `Status` record onto the victim commit using the forged `state`/`description`, or the push handler triggers a sync for `victim-org/victim-repo`'s stacks — despite the request never being signed by `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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
