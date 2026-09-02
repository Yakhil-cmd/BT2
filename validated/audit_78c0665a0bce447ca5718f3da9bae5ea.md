### Title
Webhook signature verification keyed on `repository.owner.login` while stack lookup keyed on `repository.full_name` allows cross-tenant `push` forgery via a no-secret organization - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `repository.owner.login` from the attacker-controlled JSON body, while `Handler#stacks` resolves the actual target repository/stack using the separate `repository.full_name` field. Nothing ties these two fields together, so an attacker who names an organization configured in Shipit with a blank `webhook_secret` in `repository.owner.login` gets `verify_webhook_signature` to return `true` unconditionally, while pointing `repository.full_name` at a victim repository whose stack then gets processed by `PushHandler`.

### Finding Description
The broken binding: the code implicitly assumes `repository.owner.login == owner(repository.full_name)`, but no code enforces this equality.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner)`, then `github_app.verify_webhook_signature(signature, raw_post)`. [1](#0-0) 
- `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank: `return true unless webhook_secret`. [2](#0-1) 
- Once signature checking passes, `WebhooksController#create` dispatches to handlers with the full attacker-controlled `params` hash: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 
- `PushHandler#process` resolves stacks via `Handler#stacks`, which uses `Repository.from_github_repo_name(repository_name)`, where `repository_name = payload.dig('repository','full_name')` — a completely different field from the one used for signature-org selection. [4](#0-3) [5](#0-4) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: push`, body `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/<victim-branch>", "after": "<attacker-chosen-sha>"}`, where `attacker-org` is any org entry present in Shipit's `github:` config with `webhook_secret` blank/unset (a legitimate, documented multi-org configuration per `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`, both showing `webhook_secret: # nil` as an accepted example). No `X-Hub-Signature` header (or any value) is required, since `verify_webhook_signature` short-circuits to `true` when that org's `webhook_secret` is blank. `verify_signature` passes, `PushHandler` runs against `victim-org/victim-repo`'s stack matching `branch`, and calls `stack.sync_github(expected_head_sha: params.after)` — an attacker-chosen SHA — on a stack the attacker never authenticated against.

Existing guards fail here because: `drop_unhandled_event`/`check_if_ping` don't touch this path; `ExplicitParameters` schema for `PushHandler` only requires `ref`/`after` are present, it doesn't validate consistency between `repository.owner.login` and `repository.full_name`; there is no `require_permission!`/session check on this unauthenticated webhook endpoint by design; and `Repository.from_github_repo_name` performs a straightforward lookup by `full_name` with no cross-check against the org used for verification.

### Impact Explanation
The attacker can force `sync_github` to run against an arbitrary victim stack's tracked branch by supplying a forged `after` SHA, which is used as `expected_head_sha` in the sync — this can append/advance commits and, when `review_stacks_enabled: true, allow_all` is set (auto-provisioning review stacks that execute `shipit.yml` on new branches/PRs from any contributor), drives continuous delivery/build execution on the deploy host for a repository that never authenticated the webhook. This is a payload for one repository (attacker's, or none at all — just a config entry with a blank secret) mutating another's stack/task, matching the "Critical" impact category (webhook forgery / authentication bypass leading to unauthorized sync and downstream execution). It is repeatable against any repository whose full name the attacker chooses, as long as any org entry in Shipit's config has a blank `webhook_secret` — a config state Shipit's own documentation and test fixtures show as valid/expected (single-org default config ships with `webhook_secret: # nil` too).

### Likelihood Explanation
Preconditions: (1) Shipit is configured with the multi-organization `github:` schema, and (2) at least one configured organization has no `webhook_secret` set — a state explicitly documented and present in test fixtures as acceptable, not a misconfiguration flagged anywhere in the code. (3) A victim stack must exist for some `owner/repo` with `review_stacks_enabled: true, allow_all` (or simply any tracked branch) to get amplified impact. Attacker cost is a single unauthenticated HTTP POST with no secrets, tokens, or GitHub identity required — fully within the "unprivileged internet user" threat model. It is trivially repeatable against arbitrary target repositories by just changing `repository.full_name` in the JSON body.

### Recommendation
Bind signature verification and stack resolution to the same identity. Concretely:
1. Derive the organization used for `Shipit.github(organization:)` from `repository.full_name`'s owner segment (or require it to equal `repository.owner.login` and reject mismatches with `head(422)`).
2. Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank for organizations that also route to real stacks — either require every configured org to set a `webhook_secret`, or fail closed (return `false`) rather than fail open when it's missing.
3. In `Handler#stacks`, cross-check that the resolved `Repository`'s owner/organization matches the organization that authenticated the request before processing.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push forged with a no-secret organization login syncs a victim repository's stack" do
  # Arrange: victim stack tracked at "shopify/shipit-engine" branch "master"
  victim_stack = shipit_stacks(:shipit)
  assert_equal "shopify", victim_stack.repository.owner
  assert_equal "shipit-engine", victim_stack.repository.name

  # Configure org "attacker-org" with a blank webhook_secret, per documented multi-org schema
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    Shipit::GitHubApp.new("attacker-org", { webhook_secret: nil })
  )

  forged_body = {
    "repository" => {
      "owner" => { "login" => "attacker-org" },      # used ONLY for signature org selection
      "full_name" => "shopify/shipit-engine"          # used for actual stack lookup — VICTIM repo
    },
    "ref" => "refs/heads/master",
    "after" => "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  }.to_json

  @request.headers['X-Github-Event'] = 'push'
  # No X-Hub-Signature header sent at all

  assert_no_difference -> { victim_stack.commits.count } do
    # BROKEN BINDING BEING TESTED:
    # verification_org ("attacker-org") != stack_owner_org ("shopify")
    # yet verify_webhook_signature returns true and PushHandler still runs against victim_stack
    victim_stack.expects(:sync_github).with(expected_head_sha: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    post :create, body: forged_body, as: :json
    assert_response :ok
  end
end
```
This demonstrates the invariant violation: a `push` event authenticated (trivially, via blank secret) under `attacker-org` should never be permitted to affect a stack belonging to `shopify/shipit-engine`, but `sync_github` is invoked on the victim stack regardless.

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
