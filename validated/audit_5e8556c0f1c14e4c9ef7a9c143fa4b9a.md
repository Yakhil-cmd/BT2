### Title
Cross-tenant Status forgery via unscoped SHA lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `sha` alone with `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, with no check that the commit belongs to the organization/repository that authenticated the webhook. In a multi-org Shipit deployment, a legitimate tenant of org A can send a validly-signed `status` webhook naming a SHA that belongs to a commit tracked under org B's stack, forging a `Status` record on org B's commit.

### Finding Description
The broken binding: organization that verified the webhook signature (`repository_owner` in `WebhooksController#verify_signature`, using `Shipit.github(organization: repository_owner)` and that org's `webhook_secret`) should equal the organization/stack that owns the `Commit` row being mutated. This equality is never checked.

Path:
1. `WebhooksController#verify_signature` [1](#0-0)  validates the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e. the `webhook_secret` configured for the org named in `payload['repository']['owner']['login']`.
2. In the multi-org configuration (`Shipit.github_app_config` / `Shipit.github`, see `lib/shipit.rb:170-200`), each organization has its own independent `webhook_secret`. A tenant who administers org A's GitHub App installation legitimately knows org A's `webhook_secret` and can produce a validly-signed payload claiming `repository.owner.login == "org-a"`.
3. `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event('status') => [StatusHandler]` with the raw parsed JSON, without ever re-checking which stack/repository the `sha` belongs to [2](#0-1) .
4. `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2)  — it never filters by `commit.stack.repository` or any org identifier from the verified payload.
5. `Commit#create_status_from_github!` writes a `Status` row (state/context/description/target_url attacker controlled) and can trigger `deployable_status`/`commit_status` hooks and enqueue `ProcessMergeRequestsJob`, as shown by `test/models/commits_test.rb:661-777`, which directly affects merge-gating logic.

Because `sha` is a 40-character globally-unique identifier normally, the practical trigger requires either a SHA collision (impractical) or, more realistically, an attacker who already knows/controls a real SHA that also happens to exist in a victim stack's `commits` table (e.g., a shared/forked upstream commit, a commit cherry-picked between orgs' Shipit stacks, or the attacker socially learning a victim's SHA from a public source and replaying it to their own org's authenticated webhook endpoint). Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`) only validate signature and payload shape — none scope the SHA to the authenticated repository.

### Impact Explanation
An attacker who legitimately administers one org's GitHub App installation (org A) can write a forged `Status` (`state`, `context`, `description`, `target_url` all attacker-controlled) onto any `Commit` row elsewhere in the same Shipit instance that shares that SHA, regardless of which org/stack owns it. This can flip `commit.state`/`deployable?`, trigger `ProcessMergeRequestsJob`, and influence merge-queue gating for a stack the attacker does not own — a payload for one repository mutating another's commit/stack state. This matches the "Critical: a payload for one repository mutating another's stack, commit, task or team" category, contingent on the multi-org webhook-secret configuration being used and a matching SHA existing across tenants.

### Likelihood Explanation
Requires (a) a Shipit deployment configured with the multi-organization GitHub App schema (`secrets.github.<org>.webhook_secret` per org, as documented in `docs/setup.md` "Using Multiple Github Applications"), so that different orgs have independently valid signing secrets, and (b) a SHA collision between the attacker's own repository/commit history and a real commit tracked in a victim stack. Given SHA-1's 40-hex-character space, true collisions are not feasible; the realistic trigger is limited to scenarios where the same commit SHA is legitimately known/shared across repositories (e.g., forks, mirrored/shared history) that map to different Shipit stacks under different orgs. The code-level flaw (missing repository scoping) is unconditionally present and would fire for any submitted SHA that matches a row, but the number of real-world "same SHA under different orgs" opportunities is limited, making exploitation situational rather than trivially repeatable against arbitrary stacks.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository/organization that authenticated the webhook — e.g., join through `commit.stack.repository` and compare against `payload['repository']['full_name']` (or the verified `repository_owner`), and only call `create_status_from_github!` on commits belonging to that repository/stack.

### Proof of Concept
minitest plan (single-org test config would need to be swapped for a multi-org secrets config, or the signature-verification stub bypassed as in existing tests, to isolate the missing-scoping bug):
```ruby
test ":status does not attach a status to a commit belonging to a different repository/org" do
  # Commit fixture under stack B ("cyclimse"), with a known sha
  victim_commit = shipit_commits(:cyclimse_first)
  shared_sha = victim_commit.sha

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate org A's own verified webhook

  body = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'attacker/ci',
    'description' => 'forged',
    'target_url' => 'https://attacker.example.com',
    'repository' => { 'full_name' => 'org-a/some-repo', 'owner' => { 'login' => 'org-a' } }
  }.to_json

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body:, as: :json
  end
  # Currently FAILS: StatusHandler#process matches by sha alone and creates
  # a Status on victim_commit even though the verified payload's repository
  # ("org-a/some-repo") does not match victim_commit.stack.repository.
end
```
This demonstrates the binding "organization that verified the webhook (A)" vs "organization owning the mutated Commit (B)" diverges without producing an error, because `StatusHandler#process` performs no repository check.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
