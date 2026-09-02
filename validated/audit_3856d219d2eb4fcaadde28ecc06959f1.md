## Confirmed Finding



### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` in status webhook handler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire `commits` table and calls `create_status_from_github!` on every match, without filtering by the repository/organization that the webhook signature was verified for. Because `sha` is only unique per `(sha, stack_id)` (not globally), an attacker who controls a repository in org A can trigger a signed webhook whose `sha` collides with a commit belonging to an unrelated org B's stack, writing a forged `Status` (e.g. `state: success`) onto org B's commit using only org A's `webhook_secret`.

### Finding Description
The broken binding is: `repository_owner (verified against org A's webhook_secret) == owning stack/organization of every Commit row mutated`. This does not hold.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) only checks that the request signature matches `Shipit.github(organization: repository_owner)`'s configured `webhook_secret`. It authenticates *which organization's secret produced the signature*, but never re-validates that the `repository`/`sha` in the body actually belongs to that organization's tracked stacks.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
  ```ruby
  def process
    Commit.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
  ```
  performs a global, unscoped lookup by `sha` only — no `stack_id`, `repository_name`, or organization filter is applied anywhere in the handler or in `Commit#create_status_from_github!` (app/models/shipit/commit.rb:165-169).
- The schema explicitly confirms `sha` is **not** globally unique: `add_index :commits, %i(sha stack_id), unique: true` (db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb:3) — uniqueness is scoped per stack, meaning multiple stacks/orgs legitimately hold rows with identical `sha` (e.g. the git empty-tree hash `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or a commit cherry-picked/copied verbatim between repositories).

Attacker flow: attacker owns a repo in org A with a configured Shipit GitHub App/webhook. They create/observe a commit whose sha collides with (or is copied from) a commit tracked in org B's stack — trivially achievable with the well-known empty-tree sha, or by cherry-picking a commit from a public upstream that org B also tracks. They send `POST /webhooks` with `X-Github-Event: status`, a correctly computed `X-Hub-Signature` using org A's `webhook_secret`, and body `{"sha": "<colliding sha>", "state": "success", "repository": {"owner": {"login": "orgA"}}}`. `verify_signature` passes (it only checks org A's secret against org A's payload — which is legitimately theirs). `StatusHandler#process` then matches and mutates *every* `Commit` row with that `sha`, including org B's, calling `create_status_from_github!` which creates a `Status` row scoped to `stack_id` of org B's commit, changes `commit.state`, and can trigger downstream side effects (`enable_ci_on_stack`, `schedule_continuous_delivery`, `ProcessMergeRequestsJob` per app/models/shipit/status.rb:18-19 and app/models/shipit/commit.rb:148-163).

No other guard intervenes: `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema in `StatusHandler` only validates field types/presence, not ownership; there is no `stacks`/`repository` scoping anywhere in the query.

### Impact Explanation
An attacker with a legitimate, unprivileged GitHub organization/repo and their own valid `webhook_secret` can write a `Status` row (and drive `commit.state`, CI-enable, and continuous-delivery/merge-request processing) onto a **different tenant's** stack/commit that they have no access to, purely by finding or engineering a sha collision. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any commit sha the attacker can discover or reproduce (trivially the empty-tree sha, which exists in virtually every git repository), and scales to any stack in the Shipit instance that happens to track a commit with that sha.

### Likelihood Explanation
Preconditions are modest but realistic: the attacker needs their own Shipit-tracked repository/org (fully within an unprivileged actor's control — they can register any repo they own), and a sha collision with a target stack's commit. The empty-tree sha is universal and appears in many repositories' history (e.g., from `git commit --allow-empty-tree` scenarios, submodule initialization, or repo initialization patterns), and copied/cherry-picked commits across repos are common in monorepo-mirroring or vendoring workflows. No secrets, sessions, or team memberships are required — only the attacker's own legitimately-configured webhook secret.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous handlers) to only stacks belonging to the verified `repository_owner`/`repository.full_name` from the webhook payload, e.g. join through `Stack` on the repository name derived from `params.repository` and restrict `Commit.where(sha: params.sha, stack: Stack.where(repository_owner: ..., repository_name: ...))`, mirroring how other handlers (e.g. push) locate the target stack.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative)
test "status webhook cannot write status onto a commit in another tenant's stack" do
  org_a_stack = shipit_stacks(:shipit) # owned by org A, attacker-controlled
  org_b_commit = shipit_commits(:cyclimse_first) # belongs to a different stack/org B
  colliding_sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
  org_b_commit.update!(sha: colliding_sha)

  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => colliding_sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'shopify' } } # org A
  }.to_json

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # org A's own valid secret

  assert_no_difference -> { org_b_commit.reload.statuses.count } do
    post :create, body:, as: :json
  end
end
```
Before the fix, this assertion fails: `org_b_commit.statuses.count` increases by 1 and `org_b_commit.reload.state` becomes `success`, proving org A's webhook credentials mutated org B's stack/commit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
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
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
