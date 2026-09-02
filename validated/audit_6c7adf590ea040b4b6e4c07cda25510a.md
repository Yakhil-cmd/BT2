## Title
Cross-tenant status mutation via unscoped `Commit.where(sha:)` in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` with no repository/stack filter, then calls `create_status_from_github!` on every matching row. Since `sha` is indexed on `(stack_id, sha)` and not globally unique, a single verified webhook from one repository's GitHub App can mutate commit status state in every unrelated stack that happens to contain a commit with the same sha.

### Finding Description
The broken binding: number of stacks mutated by one verified `status` webhook payload should equal 1 (`Stack.where(repository: Repository.from_github_repo_name(payload.dig('repository','full_name')))`), but the observed code produces N (every stack with any `Commit` row sharing `params.sha`).

Code path: `Shipit::WebhooksController#create` dispatches the parsed JSON to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` after `verify_signature` [1](#0-0)  checks the payload's HMAC against the GitHub App keyed by `repository_owner` (`params.dig('repository','owner','login')`) [2](#0-1) . This only proves the payload came from GitHub for *that* repository owner — it says nothing about which `Stack`/`Commit` rows should be touched.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

Unlike other handlers (e.g. `PushHandler`, the pull-request handlers), `StatusHandler` never calls the base `Handler#stacks` helper, which is the mechanism designed to scope webhook effects to the repository named in the payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [4](#0-3) 

`Commit#sha` has no global uniqueness constraint — the only index found is `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming sha is only unique per-stack, not engine-wide. `create_status_from_github!` writes a `Status` row and triggers `Hook.emit(:commit_status, ...)`, `stack.schedule_merges`, and continuous-delivery scheduling per matched commit [5](#0-4) [6](#0-5)  — all of this runs once per matching stack, regardless of whether that stack's repository is the one that signed the webhook.

No other guard closes this gap: `verify_signature` validates authenticity of origin only for the *owner org* of the payload, not the target stack; `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not scope; `drop_unhandled_event` is unrelated. None of these prevent a same-sha commit belonging to a different, unrelated repository/stack from being updated.

Attacker exploit: an attacker who owns/controls a public repository forked or based on a common upstream template (so that some commit sha, e.g. an initial commit, is shared with a victim's private/other stack) sends (or, if they can get GitHub to send, triggers via a CI status update on their own repo) a `status` event with `state=success`, `sha=<shared sha>`. The webhook is legitimately signed for the attacker's own repository/org, passes `verify_signature`, and `StatusHandler` then updates the `Status` for every stack — including the victim's — that has a `Commit` row with that sha.

### Impact Explanation
Impact is a payload from one repository mutating another (unrelated) repository's stack/commit state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." A forged/legitimate-but-foreign status update can flip a victim stack's commit to `success`, which can unblock `deployable?` checks, trigger `schedule_merges`, and feed continuous delivery (`schedule_continuous_delivery`) — potentially causing an unauthorized deploy of a commit that never actually passed CI in the victim's own pipeline. This is repeatable against any victim stack sharing a sha with an attacker-controlled repository, and scales to N stacks per single request.

### Likelihood Explanation
Preconditions: at least two stacks (attacker-controlled and victim) must contain a `Commit` row with identical `sha`. This is realistic for shared initial commits from common templates/boilerplates, or any case of forked/rebased repos with overlapping history. No Shipit secrets, API tokens, GitHub App keys, or privileged roles are required — only the ability to trigger a legitimate `status` webhook from a repository the attacker owns (e.g., via any CI integration or GitHub API call on their own repo). Attacker cost is low and the attack is repeatable at will.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the stacks associated with the payload's repository, mirroring the `stacks` helper used by other handlers, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This binds mutation strictly to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, ensuring only the stack(s) of the repository that authenticated the webhook are affected.

### Proof of Concept
Minitest plan (to be placed under `test/` — out of scope for this engine per the audit rules but illustrating expected assertions):
1. Create `Repository`/`Stack` fixtures for `repo_a`, `repo_b`, `repo_c` (three unrelated tenants).
2. Create a `Commit` in each stack sharing `sha = "deadbeef..."`.
3. POST to `/webhooks` a `status` event payload with `repository.full_name = "org/repo_a"`, `sha = "deadbeef..."`, `state = "success"`, signed with `repo_a`'s (attacker-controlled) webhook secret.
4. Assert: `Shipit::Status.where(sha: "deadbeef...").count` equals `3` under current code (bug demonstrated) vs. expected `1` (only `repo_a`'s commit status created) — i.e., assert `Shipit::Status.joins(:commit).where(shipit_commits: { stack_id: [stack_b.id, stack_c.id] }).exists?` is `false` after the fix, and currently returns `true`, proving cross-tenant mutation.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
