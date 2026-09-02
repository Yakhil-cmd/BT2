### Title
Signature verification fails open (returns `true`) for organizations with no `webhook_secret` configured, allowing unauthenticated push webhooks to mutate a stack - (File: lib/shipit/github_app.rb, app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` delegates all signature validation to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` when the target organization's `webhook_secret` is blank. Because `repository_owner` is read directly from the unauthenticated JSON body, any internet client can select which org's (secret-less) configuration is checked and then have the payload processed by `PushHandler`, enqueuing a `GithubSyncJob` against that organization's real stack with no valid `X-Hub-Signature`.

### Finding Description
The binding the engine relies on is: *the organization whose `webhook_secret` cryptographically verified the request body == the organization owning the stack that gets mutated by that body*. In `app/controllers/shipit/webhooks_controller.rb#verify_signature` [1](#0-0) , the org used for verification is taken straight from the attacker-controlled payload via `repository_owner` [2](#0-1) , and passed to `Shipit.github(organization: repository_owner)`.

`GitHubApp#verify_webhook_signature` then does:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

If that organization's `webhook_secret` is blank (`@webhook_secret = @config[:webhook_secret].presence` [4](#0-3) ), the method returns `true` unconditionally — no HMAC is computed, no secret is required, and the request passes `verify_signature` even with no `X-Hub-Signature` header at all.

Once verification "passes", `create` parses the body and dispatches it to `Shipit::Webhooks.for_event('push')`, which resolves to `PushHandler`. `PushHandler` looks up the target stacks independently, using `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` in the shared `Handler#stacks`/`#repository_name` methods [5](#0-4) , then calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the named branch [6](#0-5) .

Attacker request:
```
POST /webhooks
X-Github-Event: push
(no X-Hub-Signature header)

{"repository":{"owner":{"login":"victim-org"},"full_name":"victim-org/victim-repo"},
 "ref":"refs/heads/master","after":"<attacker-chosen sha>"}
```
Because `verify_webhook_signature` never inspects the missing header before returning `true` when `webhook_secret` is blank, and both `repository_owner` and `repository.full_name` are read from that same unauthenticated body, an attacker who never held `victim-org`'s secret (because none exists) can still get `GithubSyncJob` enqueued for `victim-org`'s real stack, causing Shipit to ingest/sync commits chosen by the attacker's `after` SHA.

No existing guard prevents this: `drop_unhandled_event` only checks the event type is handled [7](#0-6) ; `force_github_authentication`, `User#authorized?`, and `require_permission!` are irrelevant to this unauthenticated engine-level endpoint; `ExplicitParameters` in `PushHandler` only validates presence of `ref`/`after`, not authenticity of the source; and `Repository`/`Stack` model validators only constrain format, not provenance.

### Impact Explanation
An attacker can force `Shipit::GithubSyncJob` to run against any stack belonging to an organization that has no `webhook_secret` configured, without ever possessing that secret, purely by naming that organization/repository in an unauthenticated POST body. This is a genuine authentication bypass ("forged webhook accepted") matching the Critical category: "a payload for one repository mutating another's stack" / "unauthorized write into victim-org's stack by an attacker who never held victim-org's webhook_secret." It is fully repeatable against any organization in the Shipit deployment that has an unset `webhook_secret`, and scales to every stack under that organization since `PushHandler` iterates all non-archived stacks matching the branch.

### Likelihood Explanation
The only precondition is that the target organization's `Shipit::GithubHook`/`GitHubApp` config has a blank `webhook_secret` — no privileged role, session, token, or GitHub secret is required from the attacker. This is a plausible real-world configuration state (e.g., organizations onboarded without setting up HMAC signing, or environments where the secret was never provisioned), and the attack cost is a single unauthenticated HTTP POST, fully repeatable and scriptable.

### Recommendation
Make signature verification fail closed by default: treat a missing/blank `webhook_secret` as a hard misconfiguration that rejects all webhooks for that organization (or refuses to boot/register the organization) rather than returning `true` from `GitHubApp#verify_webhook_signature`. Additionally, do not let `repository_owner`/`repository.full_name` be trusted purely from the payload for org selection without a verified signature — verification should not be skippable based on attacker-supplied identifiers.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` (or an integration test), add a case where the configured `GitHubApp` for the fixture organization (e.g. `shipit_stacks(:shipit)`'s owner) has `webhook_secret` set to `nil`/blank:
```ruby
test "push with no signature and blank webhook_secret still enqueues a job (bug)" do
  Shipit.github(organization: 'shopify').stubs(:webhook_secret).returns(nil) # or configure fixture with blank secret
  request.headers['X-Github-Event'] = 'push'
  parsed_body = JSON.parse(payload(:push_master))
  expected_head_sha = parsed_body['after']

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
    post :create, body: parsed_body.to_json, as: :json # no X-Hub-Signature header set
  end
end
```
Assert before/after: before, `webhook_secret.present?` is false for the org; after posting with no signature header, `GithubSyncJob` is enqueued for `@stack.id` — demonstrating the write happened for a repository/organization that never cryptographically authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
