### Title
Webhook signature verified against the payload's `repository.owner.login`/`organization.login`, but event handlers act on the payload's independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit's `/webhooks` endpoint is unauthenticated by design and relies solely on an HMAC signature to establish trust in an inbound payload. The controller derives *which organization's secret* to use for that HMAC check from one JSON field (`repository.owner.login` / `organization.login`), but the downstream handlers that actually mutate state (find a `Stack`/`Repository` and write commit statuses, sync push refs, etc.) key off a *different*, independently-controlled JSON field (`repository.full_name`). Because these two fields are never cross-checked for consistency, an attacker who legitimately controls one Shipit-registered GitHub organization (and therefore knows/controls that organization's webhook secret) can craft a payload whose `owner.login` matches their own org (satisfying signature verification) while `repository.full_name` points at a victim organization's repository, causing the handler to act on the victim's stack.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate against purely from the payload itself: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then does a straightforward HMAC comparison scoped to whatever organization was resolved: [3](#0-2) 

Once the signature "passes" for that resolved organization, `create` hands the **entire raw payload** (not just the verified organization's data) to the event handlers: [4](#0-3) 

Every handler, however, resolves the target `Stack`/`Repository` from a completely different field, `repository.full_name`, with no comparison back to `repository.owner.login`: [5](#0-4) [6](#0-5) 

The test suite itself demonstrates that these two fields are independent inputs that can be set separately (the test merges a synthetic `repository.owner.login` value on top of a fixture that already carries its own `repository.full_name`): [7](#0-6) [8](#0-7) 

Equality that should hold but doesn't:
`organization whose secret authenticated the request (repository.owner.login / organization.login)` == `organization/repository the handler acts on (repository.full_name)`.

Before the attack: for organic GitHub-generated webhooks, GitHub itself guarantees these two fields are consistent (they both describe the same repository), so the mismatch never manifests.

After the attack: an attacker who owns/administers any GitHub organization that has been onboarded to the same Shipit instance (multi-organization support is corroborated by the `GithubOrganizationUnknown` rescue path in `verify_signature` and by the dedicated multi-app fixture `test/dummy/config/secrets_double_github_app.yml`) knows that organization's `webhook_secret` value (it is a value the org owner supplies when registering their GitHub App with Shipit). That attacker can compute a valid `X-Hub-Signature` over an arbitrary payload body using their own org's secret, set `repository.owner.login` (or `organization.login`) to their own org so `verify_signature` picks their own secret and passes, but set `repository.full_name` to `victim-org/victim-repo`. The request is POSTed directly to the public `/webhooks` endpoint (bypassing GitHub entirely, since nothing but the HMAC ties the request to GitHub).

### Impact Explanation
Handlers keyed on `repository.full_name` include, e.g., the status handler which creates `CommitStatus` records for commits, and the push handler which triggers `Stack#sync_github`. Because `ci.require`/`ci.blocking` deployability checks in Shipit are driven by stored commit statuses, an attacker able to inject a forged `status` event with `state: "success"` against an arbitrary victim commit (via the org/repo mismatch above) can make an otherwise-non-CI-passing commit appear deployable, enabling an **unauthorized deploy** of a stack the attacker has no access to. This satisfies the "unauthorized deploy" High/Critical impact criterion — the trust boundary broken is exactly the analog requested: the organization whose credential authenticated the webhook versus the repository the webhook write path actually mutates.

### Likelihood Explanation
The prerequisite is administrative control of *any* GitHub organization onboarded to the shared Shipit deployment (i.e., knowledge of that org's own configured `webhook_secret`), not any privilege on the victim's organization, repository, or Shipit account, and no `ApiClient` token or session is required — this matches the "unprivileged attacker" framing for this instance's scope (attacker only controls their own unrelated org). Crafting the forged HTTP POST with a mismatched `owner.login`/`full_name` pair is trivial once the attacker's own secret is known, since `verify_signature` performs no cross-field consistency check.

### Recommendation
In `WebhooksController#verify_signature` / `create`, after resolving `repository_owner` and validating the signature for that organization, re-derive `repository.full_name`'s owner and require it to match `repository_owner` (or `organization.login`) before dispatching to handlers; reject payloads where these fields disagree.

### Proof of Concept
1. Attacker registers/administers `attacker-org` on the shared Shipit instance and knows its configured `webhook_secret` (e.g., `s3cr3t`).
2. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/circleci"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(s3cr3t, body)` and sets `X-Github-Event: status`.
4. POSTs directly to `https://<shipit-host>/webhooks`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` from `repository.owner.login`, and the HMAC check succeeds using the attacker's own secret.
5. The status handler resolves the target repository/stack from `repository.full_name` = `"victim-org/victim-repo"` (per `Handler#repository_name`, [9](#0-8) ), and creates a forged "success" `CommitStatus` on the victim's commit, potentially unlocking deploy for that commit under `ci.require`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** test/controllers/webhooks_controller_test.rb (L216-218)
```ruby
    def repository_params
      { repository: { owner: { login: 'shopify' } } }
    end
```
