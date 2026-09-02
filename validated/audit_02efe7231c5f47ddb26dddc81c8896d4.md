### Title
Cross-tenant repository confusion in `Shipit::WebhooksController#verify_signature` allows a webhook signed by one org's (no-)secret to mutate another org's stack via `PushHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the signing/authentication scope from `payload.dig('repository', 'owner', 'login')`, while `Handler#stacks` (used by `PushHandler`) selects the mutated stack from the independent field `payload.dig('repository', 'full_name')`. Because these two fields are read from the same attacker-controlled JSON body with no cross-validation, an attacker can authenticate as an organization with no `webhook_secret` while targeting a completely different organization's/repository's stack for mutation.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't: `organization_used_to_verify_signature == owner_segment_of(repository_used_to_select_and_mutate_stack)`.

- `verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that organization's config has no `webhook_secret` set [3](#0-2) .
- Once past `verify_signature`, `PushHandler#process` (via `Handler#stacks`) resolves the *target* repository/stack using `payload.dig('repository', 'full_name')`, an entirely separate field of the same JSON body: `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) .
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack on the matching branch [5](#0-4) .

Nothing in this path enforces that `repository.owner.login` (used only to pick the `GitHubApp`/secret for signature verification) matches the owner portion of `repository.full_name` (used to pick the stack to mutate). An attacker who knows of, or controls, any organization onboarded to the Shipit instance without a configured `webhook_secret` (e.g. a low-security tenant in a multi-org Shipit deployment, or any org whose operator forgot to set one) can send:

```
POST /webhooks
X-Github-Event: push
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-with-no-secret" },
    "full_name": "victim-org/victim-repo"
  }
}
```

`verify_signature` calls `Shipit.github(organization: "org-with-no-secret")`, which returns `true` regardless of the (missing or garbage) `X-Hub-Signature` header, so the request passes with `head(422)` never called [1](#0-0) . `PushHandler` then looks up `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: ...)` on that victim stack [4](#0-3) [5](#0-4) . If the victim stack's continuous delivery/auto-deploy is configured, and the org config for `victim-org` sets `bot_login` (`Shipit.user`), the resulting deploy runs under the bot identity, amplifying the effect of the forged sync.

None of the existing guards catch this: `verify_signature` only ever checks the secret belonging to the org named in `repository.owner.login`, never the org that actually owns the mutated repository; `drop_unhandled_event` only filters by event type, not payload consistency; the `ExplicitParameters` schema for `PushHandler` only requires `ref` and `after` to be present, not that they match a repository consistent with the one used for authentication.

### Impact Explanation
This allows a payload authenticated (trivially, since no secret exists) against one repository/organization to mutate a completely unrelated stack belonging to another repository/organization — matching the rules' explicit Critical category "a payload for one repository mutating another's stack, commit, task or team." Because `sync_github` can append arbitrary attacker-chosen commits/SHAs and, when the target stack has `continuous_delivery` and a `bot_login` configured, subsequently trigger an unauthorized deploy running as the bot identity, this is repeatable against any stack/branch as long as the attacker knows (a) the victim's `owner/repo` full name (public information) and (b) any onboarded org lacking a `webhook_secret`. The blast radius spans every stack across every tenant hosted by the same Shipit instance, since the org used for authentication is decoupled from the org whose stack is mutated.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured with at least one GitHub organization that has no `webhook_secret` set (multi-tenant Shipit deployments commonly onboard several orgs with varying rigor), and a victim stack must exist for a different, targeted repository. No GitHub secrets, sessions, or API tokens are required — the attacker only needs to know the target `owner/repo` and craft a JSON POST to the public `/webhooks` endpoint. This is low-cost, fully unauthenticated, and repeatable at will.

### Recommendation
In `WebhooksController#verify_signature`, and in `Handler#stacks`/`Handler#repository_name`, derive both the signature-verification organization and the mutation-target repository from the same canonical field (e.g., always split `owner` from `repository.full_name`, or explicitly assert `repository.owner.login == full_name.split('/').first` and reject on mismatch) so a single organization's key/secret can only ever authenticate webhooks for that same organization's repositories.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, illustrative):
```ruby
test "forged push for org with no webhook_secret mutates a different org's stack" do
  # Setup: configure two orgs
  #  - "org-with-no-secret": github_apps config with no webhook_secret
  #  - "victim-org": stack exists for "victim-org/victim-repo", branch master, bot_login configured (Shipit.user)
  victim_stack = shipit_stacks(:victim) # repository full_name "victim-org/victim-repo", branch "master"

  @request.headers['X-Github-Event'] = 'push'
  # No valid X-Hub-Signature is supplied/needed
  body = {
    ref: 'refs/heads/master',
    after: 'attacker-controlled-sha',
    repository: {
      owner: { login: 'org-with-no-secret' },
      full_name: 'victim-org/victim-repo'
    }
  }.to_json

  Shipit::Stack.any_instance.expects(:sync_github).with(expected_head_sha: 'attacker-controlled-sha')

  post :create, body:, as: :json
  assert_response :ok
end
```
Assertion on both sides of the binding: before the fix, `organization_used_for_signature ("org-with-no-secret") != owner_of(full_name) ("victim-org")` yet the request still succeeds and `sync_github` is invoked on `victim_stack`; after the fix, the mismatch should cause `head(422)` and `sync_github` must never be called.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
