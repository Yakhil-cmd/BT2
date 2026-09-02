### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes a GitHub `status` webhook's context/state to **every** `Shipit::Commit` row matching the payload `sha`, without filtering by the repository that authenticated the webhook. Since `Commit` records are only unique per `(stack_id, sha)` and not globally, a status event legitimately signed for one repository/org can flip the required-context status (e.g. `ci/build` → `success`) on a same-SHA commit belonging to a completely different stack, altering that victim commit's `deployable?`/merge eligibility.

### Finding Description
The broken binding: the code assumes `commit.stack == repository_that_sent_the_webhook`, i.e. it implicitly asserts `Commit.where(sha: params.sha).stack.github_repo_name == params.dig('repository','full_name')`. That equality is never checked.

Path:
1. `Shipit::WebhooksController#create` parses the JSON body and dispatches to registered handlers for the `status` event: [1](#0-0) . `verify_signature` only validates that the payload was signed by the GitHub App registered for `repository_owner` (`params.dig('repository','owner','login')`) — it authenticates *the organization*, not the specific repository or the SHA-to-repository binding: [2](#0-1) .
2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
There is no `joins(:stack)` / `where(stack: { repository: ... })` filter tying the lookup to `params['repository']['full_name']`.
3. `Commit#create_status_from_github!` calls `add_status`, which records the new status, and — if the simple state transitions (e.g. `unknown/pending` → `success`) — triggers `stack.schedule_merges` and fires `deployable_status` hooks for **the victim stack**, not the repository that sent the event: [4](#0-3) .
4. `Commit` rows are only indexed/scoped per `(stack_id, sha)` (see `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming the same `sha` string can legitimately exist across multiple, unrelated stacks (e.g. forks, shared history, mirrored repos) — the model does not enforce global SHA uniqueness tied to one repository.
5. `deployable?` is computed directly from the aggregated `status`/`success?` state: [5](#0-4) , so injecting a fabricated `success` status for `ci/build` can flip a victim commit from non-deployable to deployable/mergeable.

Attacker flow: attacker controls (or has push/API access to) a GitHub repository under an org that Shipit already trusts (so `verify_signature` passes for that org/repo pair), and is able to produce/reference a commit object with the same SHA as a commit tracked by the victim stack (e.g., via a shared fork lineage or by replaying a real upstream commit into their own repo). They then send (or trigger CI to send) a `status` webhook with `context: ci/build`, `state: success` for that SHA. `verify_signature` succeeds because the request truly came from the attacker's own authenticated org/repo. `StatusHandler#process`, however, propagates that status to **all** `Commit` rows sharing the SHA, including the victim's, regardless of `repository.full_name`.

Existing guards checked and found insufficient: `verify_signature` (org-level, not SHA/repo-binding), `drop_unhandled_event` (irrelevant), `ExplicitParameters` schema on `StatusHandler` (only type-checks the payload, doesn't scope by repo), and there is no repository/stack filter added downstream in `Commit#create_status_from_github!` or `add_status`.

### Impact Explanation
A payload authenticated for one repository can write a `Status` record and trigger `deployable_status`/`schedule_merges` for a stack that never authenticated that event — directly matching the "payload for one repository mutating another's stack/commit" Critical category. This can flip a required CI context to `success`, unblocking `deployable?` and merge-queue processing (`stack.schedule_merges`) for an unrelated, victim-controlled commit, potentially enabling an unauthorized deploy or merge of attacker-influenced state. The attack is repeatable against any stack/commit whose SHA the attacker can reproduce or predict, and is not limited to a single victim — any tracked stack sharing that SHA is affected in one request.

### Likelihood Explanation
The attacker needs: (1) some GitHub repository/organization already integrated with this Shipit instance (so `Shipit.github(organization: repository_owner)` resolves and `verify_webhook_signature` succeeds), and (2) a commit SHA collision with a commit tracked in the victim's stack — realistic via shared git history (forks of the same upstream repo, mirrored/cloned repos, or cherry-picking an existing upstream commit into their own repo/branch). Both conditions are plausible in common enterprise GitHub setups (single org with many repos/forks sharing history), making this feasible without needing any Shipit credentials, session, or GitHub App secret.

### Recommendation
Scope the `StatusHandler#process` lookup (and any other SHA-based commit lookup driven by webhook payloads) to the repository/stack that authenticated the event, e.g.:
```ruby
def process
  Commit.joins(:stack).merge(Stack.where(repository: repository_from_payload))
        .where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
using `params.dig('repository','full_name')` (owner/name) matched against `Stack#github_repo_name`, so a status can only ever be applied to commits belonging to the stack(s) tied to the exact repository that sent the webhook.

### Proof of Concept
minitest plan (no live GitHub, stub `verify_signature` as in existing controller tests):
```ruby
test "status webhook does not affect commits from a different repository sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # requires ci/build via ci.require, e.g. stack fixture with ci_require: ['ci/build']
  victim_commit = victim_stack.commits.create!(sha: "deadbeef", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "victim work")

  attacker_stack = shipit_stacks(:cyclimse) # a different, unrelated repository/stack
  attacker_commit = attacker_stack.commits.create!(sha: "deadbeef", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "attacker work")

  # Binding under test, BEFORE:
  assert_not_equal 'success', victim_commit.reload.status.state
  refute_predicate victim_commit, :deployable?

  GithubHook.any_instance.stubs(:verify_signature).returns(true)
  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => 'deadbeef',
    'state' => 'success',
    'context' => 'ci/build',
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.repository_owner } }
  }.to_json

  post :create, body:, as: :json

  # Binding equality check AFTER: commit.stack.repository must equal payload.repository for the write to be legitimate.
  # It is not equal here, yet the victim commit was mutated:
  assert_equal 'success', victim_commit.reload.status.state, "status leaked into unrelated stack's commit"
  assert_predicate victim_commit, :deployable?
end
```
This demonstrates `StatusHandler#process` mutating `victim_commit` (belonging to `victim_stack`) purely because it shares a SHA with `attacker_commit`, even though the webhook's `repository.full_name` was `attacker_stack`'s, proving the missing repository-scoping in `app/models/shipit/webhooks/handlers/status_handler.rb`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
