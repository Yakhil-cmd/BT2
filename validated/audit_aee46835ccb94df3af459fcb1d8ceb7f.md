### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` amplified by `merge_queue_enabled` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository/stack scoping, so a `status` webhook that is validly signed for *any* GitHub organization/repo can write a CI status onto a same-SHA `Commit` record belonging to an unrelated stack. When that victim stack has `merge_queue_enabled`, a resulting green/pending state transition calls `stack.schedule_merges`, letting an attacker who merely owns a repository sharing a commit SHA with the victim (e.g. a shared base branch/fork) force merge-queue progression on a stack they never authenticated for.

### Finding Description
The broken binding is: **the equality `commit.stack.github_repo_name == payload.repository.full_name` is never checked before `create_status_from_github!` is applied**, i.e. `StatusHandler` treats "SHA exists in the DB" as sufficient authorization instead of "SHA exists in the DB *and* belongs to the repository that authenticated this webhook."

Code path:
1. `Shipit::WebhooksController#create` parses the payload and dispatches to handlers after `verify_signature` [1](#0-0) .
2. `verify_signature` validates the HMAC using `Shipit.github(organization: repository_owner)` — this proves the request came from GitHub for *some* repository under that organization's webhook secret, not that it matches any specific target commit's repository [2](#0-1) .
3. `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query is global across all stacks/repositories, keyed purely on the bare `sha` string, with no `stack_id`/`repository` filter [3](#0-2) .
4. `Commit#create_status_from_github!` writes the status and calls `add_status`, which — on a state transition to pending or success — invokes `stack.schedule_merges` [4](#0-3) [5](#0-4) .

Because commit SHAs are content-addressed (identical commit content across forks/shared branches yields identical SHA), an attacker who legitimately owns/controls a GitHub repository (any org where the app's webhook secret is valid) can create a commit whose SHA is shared with — or push/label a PR reusing — a SHA already tracked in a victim's stack, then trigger GitHub to emit (or forge, since verification is per-organization not per-repository/commit) a `status` event with `context: ci/kubernetes` and `state: success` for that SHA. `StatusHandler` applies it to every `Commit` row with that SHA regardless of which stack/repository it belongs to. If the victim stack has `merge_queue_enabled: true` and was waiting on `ci/kubernetes`, this write flips the required-status gate and fires `schedule_merges`, causing an unauthorized merge/ship decision on a stack the attacker never authenticated against.

None of the existing guards close this gap: `verify_signature` only proves organization-level webhook authenticity, not repository-to-commit binding; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, `context`, etc.), not ownership; there is no `require_permission!`/`stacks` scope check inside `StatusHandler`, and no model validation on `Commit`/`Status` ties the write back to the requesting repository.

### Impact Explanation
A payload authenticated for one repository can mutate CI state (`Status`) belonging to another stack/repository, which is explicitly listed as Critical impact ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge"). Combined with `merge_queue_enabled`, this can trigger `stack.schedule_merges`, i.e., an unauthorized merge decision on the victim stack. The attack is repeatable against any stack/commit sharing a SHA with an attacker-controlled repository, and the blast radius spans every stack across every tenant sharing the Shipit instance's webhook-authenticated organizations.

### Likelihood Explanation
Preconditions: the attacker needs (a) the ability to get a validly signed `status` webhook delivered — trivially satisfied for their own repositories under an org configured in Shipit, since GitHub itself signs and sends these events for repos they push commits/PRs to — and (b) a SHA collision/overlap with a victim stack's tracked commit (realistic via shared base branches, forked repos, cherry-picks, or monorepo forks where identical commits appear in multiple stacks) plus `merge_queue_enabled: true` on the victim stack requiring `ci/kubernetes`. Attacker cost is low (push a commit / open a PR from an already-onboarded repo); no Shipit session, API token, or secret is required. This is repeatable at will.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous handlers) by repository, not bare SHA — e.g., resolve the target stack(s) via `payload.repository.full_name` and restrict `Commit.where(sha:, stack_id: matching_stack_ids)` before calling `create_status_from_github!`, mirroring how other handlers must already correlate the payload's `repository` field to a specific `Stack`/`Repository` record.

### Proof of Concept
Minitest plan (no live GitHub):
```ruby
test "status webhook does not affect stacks of a different repository sharing a SHA" do
  shared_sha = "a" * 40

  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_stack.update!(merge_queue_enabled: true)
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")

  attacker_stack = Shipit::Stack.create!(repository: Shipit::Repository.new(owner: "attacker", name: "evil-repo"), environment: "production")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker commit")

  # Binding under test:
  # commit.stack.github_repo_name (victim) == payload.repository.full_name (attacker) -> should be FALSE
  assert_not_equal victim_commit.stack.github_repo_name, "attacker/evil-repo"

  Shipit::Stack.any_instance.expects(:schedule_merges).never # expectation BEFORE trace, will fail proving the bug

  payload = { "sha" => shared_sha, "state" => "success", "context" => "ci/kubernetes" }
  Shipit::Webhooks::Handlers::StatusHandler.new.call(ExplicitParameters.for(payload))

  victim_commit.reload
  assert_equal "success", victim_commit.state, "victim commit state was mutated by an attacker-authenticated payload"
end
```
This demonstrates that `StatusHandler#process`'s unscoped `Commit.where(sha:)` lookup lets an attacker-authenticated webhook mutate `victim_commit`'s status and trigger `schedule_merges` on `victim_stack`, even though the two commits belong to entirely different repositories.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
