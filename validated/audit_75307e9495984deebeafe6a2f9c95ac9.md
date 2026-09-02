### Title
Webhook signature verification is scoped to the payload's own `repository.owner.login`, allowing cross-organization/cross-repository writes when any configured GitHub organization has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's HMAC secret to check against by reading `repository.owner.login` out of the *same unverified JSON body* it is about to validate, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization has no `webhook_secret` configured. Because the downstream event handlers act on other, unrelated fields of the same forged payload (`repository.full_name`, commit SHAs, etc.) without re-checking that they belong to the organization whose key "authenticated" the request, a payload can be crafted where the field used to pick the verification key and the field used to decide what gets written are inconsistent. This breaks the binding: `organization that authenticated == repository that is written`.

### Finding Description
The controller flow is: [1](#0-0) 

`repository_owner` is derived purely from the untrusted request body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a `GitHubApp` configured per-organization, and each organization can independently have no `webhook_secret` set (this is an explicitly supported, documented configuration state): [3](#0-2) 

When an organization has no secret configured, signature verification is bypassed entirely: [4](#0-3) 

Once `verify_signature` passes, `create` parses the *same* body a second time and dispatches to handlers keyed only by `X-Github-Event`, with no re-validation that the payload's `repository` actually belongs to the organization that was "authenticated": [5](#0-4) 

Handlers act on `repository.full_name` (which can name any repository/stack tracked by this Shipit instance, in any configured org) to enqueue sync jobs, and the engine even auto-creates repository records for unknown repos on push events, as covered by the test suite: [6](#0-5) 

**The break:** `repository_owner` (used to pick the verification secret) and `repository.full_name` (used by handlers to determine which stack/commits/statuses get written) are two independent, attacker-controlled fields inside the same forged JSON body. Nothing ties them together. If *any* organization configured on the Shipit instance has a blank `webhook_secret` (a supported configuration, per `config/secrets.development.shopify.yml`), an attacker can set `repository.owner.login` to that unsecured organization to sail through `verify_signature`, while setting `repository.full_name`/other payload fields to target a stack that belongs to an entirely different, secured organization.

### Impact Explanation
This crosses a repository/organization trust boundary with no credentials: a permissionless attacker can forge `push`, `status`, `check_suite`, or `membership` webhook events that are accepted as "verified" (because the org named in `repository.owner.login` has no secret) but whose effects (queuing `GithubSyncJob`, creating `Status` records, creating `Team`/`Membership`/`User` records, auto-creating `Repository` rows) are applied against a completely different, unrelated repository/stack that the attacker has no legitimate relationship with. This is a cross-repository write into Shipit's tracked state (commit statuses, sync triggers, team memberships) — matching the "cross-repository writes" impact criterion.

### Likelihood Explanation
Likelihood depends on the specific deployment having at least one configured GitHub organization with a blank `webhook_secret` (explicitly supported by the sample config) while other organizations/stacks on the same instance are meant to be protected by their own secrets. Multi-organization Shipit instances are a documented, supported use case (`Shipit.github(organization:)`, `oauth.teams` per org), so this is a realistic configuration, not a contrived edge case. No credentials, session, or GitHub App key are required by the attacker — only knowledge (or a guess) of which configured organization lacks a webhook secret, or any org where a leaked/guessable HMAC secret can sign a payload naming a different org's repo in `full_name`.

### Recommendation
Do not use an attacker-controlled field from the unverified payload to select the verification key and then use a different attacker-controlled field to decide what gets written. Either:
1. Verify the signature against a Shipit-wide/single, or per-repository, secret that is looked up from a value the attacker cannot forge independent of the write target (e.g., look up the secret using `repository.full_name`, and cross-check `repository.owner.login` matches the owner segment of `full_name` before proceeding), or
2. Require every configured organization to have a non-blank `webhook_secret`, removing the unconditional bypass in `GitHubApp#verify_webhook_signature`, and additionally assert `repository.full_name`'s owner segment equals `repository_owner` before dispatching to handlers.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `securedorg` (has `webhook_secret` set) and `openorg` (has `webhook_secret: nil`, a supported config as shown in `config/secrets.development.shopify.yml`).
2. Attacker (no credentials, no GitHub App access) sends a `POST` to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "repository": { "owner": { "login": "openorg" }, "full_name": "securedorg/private-repo" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/main"
}
```
3. `repository_owner` resolves to `"openorg"`; `Shipit.github(organization: "openorg").verify_webhook_signature(...)` returns `true` unconditionally because `openorg` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`).
4. `create` proceeds and dispatches the `push` handler using `repository.full_name == "securedorg/private-repo"`, enqueuing `GithubSyncJob` for the `securedorg/private-repo` stack (or auto-creating the repository if untracked, per `webhooks_controller_test.rb:12-21`) — all without ever validating a signature tied to `securedorg`.

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

**File:** config/secrets.development.shopify.yml (L5-18)
```yaml
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

**File:** test/controllers/webhooks_controller_test.rb (L12-32)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end

    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```
