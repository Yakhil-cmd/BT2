### Title
Webhook organization used for signature verification is decoupled from the repository the event payload writes to - allowing cross-repository status/event forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController` selects which GitHub App/organization secret to use for HMAC verification from one payload field (`repository.owner.login`), but the event handlers that actually mutate Shipit state act on a *different, independently attacker-controlled* payload field (`repository.full_name`). Because these two fields are never cross-checked, and because signature verification is a silent no-op whenever the selected organization has no `webhook_secret` configured, an attacker with no Shipit credentials can craft a webhook whose "authenticating organization" is one they control (or one with no secret) while the "repository written" is an unrelated, victim-tracked stack.

### Finding Description
`WebhooksController#verify_signature` determines which GitHub App config to use purely from the payload: [1](#0-0) 

```
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

That value is used to look up the `GitHubApp` instance and verify the `X-Hub-Signature`: [2](#0-1) 

Signature verification itself is a no-op when the resolved organization has no configured secret: [3](#0-2) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Once `verify_signature` passes, `create` re-parses the entire raw body and dispatches it, unmodified, to the registered handlers for the event type: [4](#0-3) 

The handlers (e.g. the `status` handler) then act on a *different* field of the same payload — `repository.full_name` / `sha` — to locate the `Commit`/`Stack` to mutate, entirely independent of `repository.owner.login`: [5](#0-4) 

```
test ":state create a Status for the specific commit" do
  ...
  body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
  assert_difference 'commit.statuses.count', 1 do
    post :create, body:, as: :json
  end
  ...
end
```

Nothing binds `repository.owner.login` (the value used to select the verifying secret) to `repository.full_name` (the value used to resolve which tracked repository/commit is written to). Both are supplied by the same untrusted, attacker-controlled JSON body. This breaks the equality that should hold:
`organization that authenticated == repository that is written`.

### Impact Explanation
An attacker who knows (or can leave blank) the `webhook_secret` for *any* organization configured in the Shipit instance (including one they register/own, if multi-tenant, or one that was left unconfigured) can produce a payload that:
- sets `repository.owner.login` / `organization.login` to that organization (so `verify_signature` either trivially succeeds via a valid HMAC computed with the known secret, or is skipped entirely because `webhook_secret` is blank), and
- sets `repository.full_name` (and `sha`, `state`, `description`, `context`, etc.) to point at a **victim** repository/stack tracked by Shipit.

For the `status` event this lets the attacker inject a forged `success` CI status for an arbitrary commit on a repository they do not control and were never authenticated against. Since deploy eligibility (`Commit#deployable?`, `required_statuses`) is driven by these `Status` records, this can make a commit appear CI-green when it isn't, enabling an **unauthorized deploy** of unreviewed/unvetted code — one of the explicitly listed Critical impacts. Other events (`push`, `check_suite`, `pull_request`, `merge`) dispatched through the same controller are similarly exposed to cross-repository targeting because their resolution of "which repository/stack to act on" is likewise driven by attacker-supplied `repository.full_name`, not the organization whose secret was verified.

### Likelihood Explanation
Likelihood is Medium: it does not require any Shipit session, ApiClient token, or repository write access — only knowledge of, or the absence of, a `webhook_secret` for some organization known to the Shipit instance's GitHub App configuration. Multi-org/self-hosted Shipit deployments commonly have some organizations configured with `oauth`/app credentials but without a webhook secret set (the code explicitly supports and silently accepts this case), making the "no secret configured" path realistic in practice.

### Recommendation
1. Cross-validate that the field used to select/verify the webhook signature (`repository.owner.login`) matches the field(s) handlers use to resolve the target repository (`repository.full_name`) before dispatching to handlers; reject the request if they diverge.
2. Do not silently treat a missing `webhook_secret` as "verification passed" — either require every configured GitHub App/organization to have a secret, or refuse to process events whose target repository does not belong to the organization that was actually verified.
3. Resolve the target `Stack`/`Repository` first (from `repository.full_name`), then verify the signature using the secret configured for *that resolved repository's organization*, not an org name taken from an unrelated field of the same unverified payload.

### Proof of Concept
1. Configure/identify an organization `attacker-org` in `Shipit.github_apps` config that has no `webhook_secret` (or whose secret is known).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://example.com"
}
```
No valid `X-Hub-Signature` for `victim-org` is required — `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) resolves the GitHub App using `attacker-org` (app/controllers/shipit/webhooks_controller.rb:59-62), and `verify_webhook_signature` (lib/shipit/github_app.rb:76-83) returns `true` because `attacker-org` has no secret.
3. `create` dispatches the parsed body to the `status` handler unmodified (app/controllers/shipit/webhooks_controller.rb:10-15), which creates a `Status` record for the commit belonging to `victim-org/victim-repo`, as demonstrated by the existing test at test/controllers/webhooks_controller_test.rb:42-59 (which shows the handler trusts payload fields like `sha`, `state`, `context` directly to create the `Status`).

Note: I was not able to directly inspect `app/models/shipit/webhooks/handlers/status_handler.rb`'s source (only its test) due to index coverage limits; a Devin session with full repository access should confirm the exact repository-resolution logic in that handler and the `push_handler.rb` before implementing the fix.

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
