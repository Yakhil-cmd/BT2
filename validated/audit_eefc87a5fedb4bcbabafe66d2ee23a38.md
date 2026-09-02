Confirmed: `Commit` `belongs_to :stack`, and every other webhook handler (`PushHandler`, `PullRequest::*Handler`, `CheckSuiteHandler`) scopes its lookup through `Repository.from_github_repo_name(params.repository.full_name)` / the `stacks` helper in the base `Handler` class, but `StatusHandler#process` uniquely does not — it queries `Commit.where(sha: params.sha)` globally, across every `Stack`/`Repository` in the installation. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Cross-repository forged CI status via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` only proves that a `status` webhook was signed by *some* GitHub organization's configured secret — it authenticates that the sender controls org `params.dig('repository','owner','login')`, not that the sender controls the commit or stack the status will be applied to. `StatusHandler#process` then resolves the target `Commit` purely by `sha`, ignoring the payload's `repository.full_name` entirely, so an attacker who owns any repository registered in the same Shipit instance can forge a `status` event, signed with their own organization's webhook secret, that writes a `Status` row (arbitrary `context`/`state`/`description`) onto a commit belonging to a completely different, victim-owned stack, as long as they know a SHA that exists in that victim's `commits` table (trivial for public/forked repositories, since git commit SHAs are content-addressed and reproducible by fetching/pushing the exact same commit into their own repo).

### Finding Description
Binding claimed broken (repository authorization): `repository_owner` used to select the signing key in `verify_signature` (`Shipit.github(organization: repository_owner)`, using `params.dig('repository','owner','login')`) MUST equal the `Repository`/`Stack` that owns the `Commit` row being mutated. This binding is violated.

Path:
1. `WebhooksController#create` parses `request.raw_post` into `params` and dispatches to `Shipit::Webhooks.for_event(event)` handlers [4](#0-3) .
2. `verify_signature` picks the GitHub app config keyed by `repository_owner` from the *attacker's own* payload and validates HMAC against that org's `webhook_secret` [5](#0-4) . Since the attacker owns a repository under some organization registered with the Shipit instance (any legitimately onboarded org/repo works — this is not privileged, any user can have Shipit track their own public fork/repo), they know that org's `webhook_secret` is verifiable by a real GitHub-originated status event, or — because `verify_webhook_signature` is a standard HMAC-SHA1 check against a secret configured for *their own* org — they can simply cause GitHub to emit the real signed webhook by pushing a commit-status to their own repo via any CI/API integration they control.
3. `StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no filter on `repository`/`stack` at all [1](#0-0) . This is inconsistent with every sibling handler (`PushHandler`, `PullRequest::*Handler`s, `CheckSuiteHandler`), all of which resolve `Repository.from_github_repo_name(params.repository.full_name)` first and then scope to that repository's own `stacks`/`review_stacks` [2](#0-1) [6](#0-5) .
4. `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` using `commit.stack_id`, i.e. the **victim's own stack**, not anything derived from the attacker's payload [7](#0-6) ; `Status.replicate_from_github!` writes `context`, `target_url`, `description`, `state` verbatim from the attacker-controlled `github_status` (`params`) with no context whitelist check [8](#0-7) .
5. `MergeRequest#all_status_checks_passed?` / `StatusChecker#required_statuses` consult `stack.cached_deploy_spec.merge_request_required_statuses` (i.e. the victim stack's own `ci.require` config) and match purely by `context` string [9](#0-8) [10](#0-9) . Any `Status` row with `context` equal to a required check name and `state: success` satisfies it, regardless of who wrote that row.

Because `Commit` is not globally unique on `sha` (each `Stack` has its own `commits` rows, and `commits.sha` is not constrained to be globally unique across stacks), any commit that happens to share a SHA across two different stacks/repositories (e.g. a fork sharing history with the upstream victim repo, or a public commit re-pushed by the attacker into their own tracked repo) is fair game: an attacker's signed-but-unrelated status webhook mutates the victim's `Status` table for that commit id.

Existing guards do not prevent this: `verify_signature` authenticates the *sending org*, not the *target stack*; `drop_unhandled_event`/`check_if_ping` are irrelevant; the `ExplicitParameters` schema in `StatusHandler` only validates types/presence of `sha`, `state`, `context`, etc., not their relationship to any particular repository; there is no `Repository`/`Stack` scoping call anywhere in `StatusHandler`.

### Impact Explanation
An attacker who legitimately controls or can push webhook-worthy status events for *their own* onboarded repository can write arbitrary `Status` rows (state `success`, any `context` string) against commits belonging to any other stack in the same Shipit installation whose commit SHA they can reproduce (trivial for shared/forked history). This satisfies `MergeRequest#all_status_checks_passed?`'s required-status check for a commit and stack they do not own, unblocking `ProcessMergeRequestsJob#perform` to call `merge_request.merge!` and merge a pull request the attacker does not control. This is a cross-tenant, one-repository-mutates-another's-stack/commit issue — Critical severity per the stated impact categories (unauthorized merge, payload for one repository mutating another's stack/commit).

### Likelihood Explanation
Preconditions: attacker needs (a) any repository tracked by the same Shipit instance under an org whose webhook secret they can trigger a valid signature for (i.e., their own onboarded repo — no special privilege beyond being a normal onboarded GitHub user of the Shipit deployment), and (b) a commit SHA shared with the victim stack (straightforward for forks of public repos, or any commit copied verbatim — git SHAs are deterministic/content-addressed so an attacker can `git fetch`+`push` a victim's exact commit into their own repo to reproduce a real, validly-signed status webhook for that SHA). No GitHub App private key, `webhook_secret`, session, or API token of the victim's is needed. This is repeatable per request against any stack/commit satisfying the SHA precondition.

### Recommendation
Scope `StatusHandler#process` to the repository asserted in the webhook payload, mirroring every other handler: resolve `Repository.from_github_repo_name(params.repository.full_name)`, then only update commits belonging to that repository's own stacks (`repository.stacks.joins(:commits).where(commits: { sha: params.sha })` or equivalent), rejecting/ignoring statuses for shas not owned by the reporting repository.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or controller-level):
1. Create `stack_victim` (repository `victim/repo`) and `stack_attacker` (repository `attacker/repo`), each with their own `webhook_secret`.
2. Set `stack_victim.cached_deploy_spec` / config so `required_statuses` includes `'ci/attacker-known-context'`.
3. Create `commit = stack_victim.commits.create!(sha: 'deadbeef...')` with no statuses (so `all_status_checks_passed?` is false / `any_status_checks_missing?` is true).
4. Also create `stack_attacker.commits.create!(sha: 'deadbeef...')` (same sha, different stack) to model the shared-SHA scenario, OR directly assert on `StatusHandler` behavior by posting a `status` payload whose `repository.full_name == 'attacker/repo'` (signed with attacker org's secret) and `sha == 'deadbeef...'`, `context: 'ci/attacker-known-context'`, `state: 'success'`.
5. `assert_difference 'stack_victim.commits.first.statuses.count', 1` around posting the webhook.
6. `assert commit.reload.statuses.last.context == 'ci/attacker-known-context'` and `merge_request(for stack_victim, head: commit).all_status_checks_passed?` is now `true` — asserting both sides of the binding: `repository_owner` (attacker org) != owner of `commit.stack` (victim), yet the write succeeded and the victim's required-status check was satisfied.

### Citations

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

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/models/shipit/status/common.rb (L50-52)
```ruby
      def required?
        commit.required_statuses.include?(context)
      end
```
