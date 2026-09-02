### Title
Webhook `StatusHandler#process` writes cross-repository Statuses via an unscoped SHA lookup, unlike the polling path `Commit#refresh_statuses!` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Commit#refresh_statuses!` only ever pulls statuses that GitHub itself returns for the commit's own repository (`stack.github_api.statuses(github_repo_name, sha, ...)`), so the "this status belongs to this stack's repo" guarantee is enforced implicitly by the scoped API call. `Webhooks::Handlers::StatusHandler#process` reaches the exact same sink, `Commit#create_status_from_github!` → `Status.replicate_from_github!`, but selects target commits with `Commit.where(sha: params.sha)` — a global, cross-stack, cross-repository query with zero repository filtering.

### Finding Description
The binding that should hold is:
`{commits mutated by refresh_statuses!} == {commits c | c.stack.github_repo_name == <repo actually queried by GitHub API>}`
versus what actually happens on the webhook path:
`{commits mutated by StatusHandler#process} == {commits c | c.sha == params.sha}` (no repository/stack constraint at all).

`refresh_statuses!` at [1](#0-0)  is safe because the GitHub API call itself is scoped to `github_repo_name`, so GitHub guarantees any status returned actually belongs to that repo/sha pair.

`StatusHandler#process` at [2](#0-1)  performs no such scoping: it queries `Commit.where(sha: params.sha)` across the entire `commits` table (all stacks, all repositories) and calls `commit.create_status_from_github!(params)` for every match, even though the base `Handler` class exposes a `stacks`/`repository_name` helper derived from the webhook payload's `repository.full_name` that is never used here [3](#0-2) .

Both paths terminate in the same sink: [4](#0-3)  calling [5](#0-4) , which does `find_or_create_by!(stack_id:, state:, ...)` using the target commit's own `stack_id` — it never checks that the webhook's `repository` field matches that stack's repo.

`verify_signature` [6](#0-5)  only proves the payload was HMAC-signed by the GitHub App configured for `repository_owner` (the organization named in the payload). It says nothing about which repository *within* that organization the sha belongs to, and it cannot detect that the sha in the payload collides with a commit that already exists under a different tracked stack (per the referenced prior SHA-collision precondition). Given that precondition, this question shows the last remaining check — the implicit repo-scoping that `refresh_statuses!` gets "for free" from the GitHub API — is simply absent on the webhook path.

### Impact Explanation
Given the SHA-collision precondition (a real, GitHub-signed `status` webhook for a commit/sha the attacker legitimately controls, whose sha value collides with a commit already tracked under an unrelated stack), the webhook handler writes a `Status` row against the victim stack's commit with attacker-chosen `state`, `context`, `description`, `target_url`, and `created_at`. This can flip `commit.state` to `success`, satisfy `deployable?`/CI gating on a stack the attacker has no relationship to, and trigger `ProcessMergeRequestsJob` or continuous-deployment scheduling [7](#0-6) . This is a cross-repository write into another team's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Requires the SHA-collision precondition already established elsewhere (attacker must control a repository whose commit sha collides with a commit in the victim stack) plus a validly-signed webhook for that event, which the attacker can trivially obtain by acting on their own repository (GitHub signs it with the real per-organization `webhook_secret`, which the attacker never needs to know). No Shipit session, API token, or team membership is needed. The bug itself (unscoped `Commit.where(sha:)`) is unconditional given that precondition and is repeatable against any stack whose tracked commit sha the attacker can reproduce.

### Recommendation
Scope `StatusHandler#process` (and any other sha-only handler) by repository: resolve target stacks via the existing `stacks` helper (`Repository.from_github_repo_name(repository_name)`) and restrict the `Commit.where(sha:)` query to `stack_id: stacks.select(:id)` (or iterate `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`) so a webhook can only ever create a `Status` for commits belonging to the repository named in its own payload, mirroring the implicit scoping already enforced by `refresh_statuses!`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "StatusHandler injects a Status into an unrelated stack via SHA-only match" do
  victim_stack = shipit_stacks(:shipit)                     # repo: shopify/shipit-engine
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, message: "victim", author: Shipit::AnonymousUser.new, committer: Shipit::AnonymousUser.new, authored_at: Time.now, committed_at: Time.now)

  # Prove refresh_statuses! is safe: GitHub's own API for the victim's real repo returns nothing.
  Shipit.github.api.expects(:statuses).with(victim_stack.github_repo_name, victim_commit.sha, per_page: 100).returns([])
  assert_no_difference "victim_commit.statuses.count" do
    victim_commit.refresh_statuses!
  end

  # Attacker sends a validly-signed webhook claiming to be about a DIFFERENT repository,
  # but the sha collides with victim_commit's sha.
  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "attacker-ci",
    "repository" => { "full_name" => "attacker-org/unrelated-repo" }
  }

  handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

  assert_difference "victim_commit.statuses.count", 1 do
    handler.process
  end
  assert_equal "success", victim_commit.reload.state
end
```
This demonstrates: (1) the trusted polling path (`refresh_statuses!`), scoped to the victim's real repo via the GitHub API, correctly creates zero statuses; (2) the untrusted webhook path (`StatusHandler#process`), which never checks `payload["repository"]` against the matched commit's stack, still injects a `Status` and flips `victim_commit.state` — confirming the two "same code path" claims diverge exactly as the question states.

### Citations

**File:** app/models/shipit/commit.rb (L156-163)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
      end
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

**File:** app/models/shipit/commit.rb (L763-777)
```ruby

```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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
