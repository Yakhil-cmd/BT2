Confirmed: `commit.create_status_from_github!(params)` uses `commit.stack_id` from the commit's own `belongs_to :stack` association [1](#0-0) , not the `repository_owner` from the webhook payload, so any commit matching the forged `sha` gets its status written regardless of which org authenticated the request.

### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` combined with secret-less organizations - (File: app/models/shipit/webhooks/handlers/status_handler.rb, lib/shipit/github_app.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone with no repository/organization scoping, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever an organization is configured without a `webhook_secret`. An attacker who controls a repository under such an unsecured organization can craft a commit with an identical SHA to one in a victim's tracked stack (SHA depends only on tree/parents/message/timestamps, not on which repository holds it) and forge a `status` webhook that writes a `Status` record onto the victim's commit/stack.

### Finding Description
The claimed binding is: *the organization that cryptographically authenticated a webhook (`repository_owner` in `Shipit::WebhooksController#verify_signature`) equals the organization/repository whose data is mutated by the corresponding handler*. This binding is broken for `status` events.

- `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature`: [2](#0-1) . `GitHubApp#verify_webhook_signature` explicitly bypasses HMAC verification when no `webhook_secret` is configured for that organization: [3](#0-2) . So any organization added to `Shipit.github_apps`/config without a `webhook_secret` will accept **any** payload/signature as "verified" for that org's `repository_owner`.
- Once verified, `StatusHandler#process` does not check `params.dig('repository', ...)` against the commit's actual owning stack/repository at all; it only matches on `sha`: [4](#0-3) . `Commit#create_status_from_github!` then writes the status using the commit's own `stack_id`, not anything from the request: [1](#0-0) .
- Because git commit SHAs are a pure function of content (tree, parents, author/committer, message/timestamps) and not of which repository stores them, an attacker who can read a target commit's exact metadata (e.g., from a public repo tracked by the victim stack) can reconstruct a byte-identical commit inside their own repository under the secret-less org, then submit a forged `status` webhook for that org referencing the shared SHA. `Commit.where(sha: ...)` will match the victim's `Commit` row and `create_status_from_github!` will create a `Status` on the victim stack.

Regarding the "unknown-organization" half of the combined claim: I verified this path does **not** provide an exploitable gap. `head(422)` in the `rescue Shipit::GithubOrganizationUnknown` branch of the `before_action :verify_signature` does halt the Rails callback chain (a `before_action` that renders/heads a response is not followed by the controller action), and this is asserted directly by the existing test `"unknown github organization logs and returns unprocessable entity"`, which expects `assert_response :unprocessable_entity` and never invokes any handler: [5](#0-4) . So `create` — and therefore `StatusHandler`/`Commit.where` — is never reached in the unknown-org case; that stated "verification gap" does not exist in this codebase.

### Impact Explanation
An attacker with no privileges beyond owning a GitHub repository under an org that a Shipit operator misconfigured without `webhook_secret` can inject arbitrary `Status` rows onto commits belonging to a completely different, secured stack, as long as they can reproduce a matching SHA. This is a write for a repository that did not authenticate the request — matching the "payload for one repository mutating another's stack/commit" Critical category — since forged CI status can influence continuous-deployment gating (`Commit#create_status_from_github!` triggers `enable_ci_on_stack`, `schedule_continuous_delivery`) for the victim's stack. Blast radius is limited to organizations an operator has configured with no `webhook_secret`, and to commits whose SHA the attacker can reproduce (feasible when source is public or otherwise known, since SHAs are content-derived, not secret).

### Likelihood Explanation
Requires: (1) a Shipit operator to have configured at least one GitHub organization without a `webhook_secret` (an operator/config precondition, not attacker-controlled), and (2) the attacker to construct a commit with matching tree/parents/author/committer/timestamps/message to a target commit, then push it to a repository they control under that org and trigger/forge the `status` webhook. Constructing a byte-identical commit is feasible for public repositories or when commit metadata is otherwise known, but is not push-button for arbitrary private commits (attacker needs exact metadata). No signature verification blocks the request once the org lacks a secret, so cost per attempt is a single unauthenticated HTTP POST.

### Recommendation
1. In `StatusHandler#process` (and other handlers that key purely off `sha`), scope `Commit` lookups to the repository/organization that authenticated the request (`params.dig('repository', 'full_name')`/`repository_owner`) via the associated `Stack`/`Repository`, not `sha` alone.
2. In `GitHubApp#verify_webhook_signature`, do not silently return `true` when `webhook_secret` is blank; either require a secret for any configured organization or fail closed (reject the webhook) instead of accepting it unconditionally.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb`:
```ruby
test "status event for an org without webhook_secret can write status onto another stack's commit via shared sha" do
  victim_commit = shipit_commits(:first) # belongs to shipit_stacks(:shipit)
  # Simulate an org configured with no webhook_secret: verify_webhook_signature returns true unconditionally
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', {}) # no webhook_secret key => verify_webhook_signature always true
  )

  request.headers['X-Github-Event'] = 'status'
  forged_payload = {
    'sha' => victim_commit.sha, # attacker reproduced this sha in their own repo
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker-org/evil-repo' }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: forged_payload, as: :json
  end
  assert_response :ok
end
```
This asserts the equality-violation directly: a `status` payload authenticated (trivially) only for `attacker-org` mutates `victim_commit`, which belongs to `shipit_stacks(:shipit)` — a stack never authenticated by that org's (non-existent) secret.

### Citations

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```
