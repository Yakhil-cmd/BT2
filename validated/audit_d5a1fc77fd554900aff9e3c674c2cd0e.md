### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a GitHub status to using `Commit.where(sha: params.sha)` with no repository/stack scoping, even though the webhook signature verification only proves the payload came from GitHub for the *sending* repository/organization. Any commit row in the database that happens to share the same sha — regardless of which stack or repository it belongs to — gets its status rewritten, breaking `Commit#blocked?` for stacks the attacker never authenticated for.

### Finding Description
The intended binding is: `payload.dig('repository', 'full_name') == commit.stack.repository.full_name` for every `Commit` mutated by a webhook. This binding is never enforced for status events.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) only proves the request was signed by GitHub for `repository_owner` (the org/owner named in the payload). It says nothing about which `Commit`/`Stack` rows may be touched.
- `Webhooks::Handlers::Handler` provides a `stacks` helper (app/models/shipit/webhooks/handlers/handler.rb:32-34) that scopes lookups to `Repository.from_github_repo_name(repository_name)` — i.e., only stacks belonging to the repository that authenticated the webhook.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) does **not** use `stacks`. It runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which matches every `Commit` row across the whole database with that sha, independent of `stack_id`/repository.
- `Commit#create_status_from_github!` → `Status.replicate_from_github!` (app/models/shipit/status.rb:24-33) then creates/updates a `Status` row on that `Commit`, tagged with `stack_id`, `context`, `state`.
- `Commit#blocked?` (app/models/shipit/commit.rb:231-237) evaluates `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)`, so any older undeployed commit whose status was just overwritten changes the result for every newer commit in that stack.

Exploit flow: `Commit` rows sharing an identical sha across two different stacks/repositories are a realistic occurrence in Shipit (e.g., a PR/review-stack commit whose sha is identical in the contributor's fork and in the tracked base repository, or two stacks tracking overlapping history). The attacker:
1. Opens a PR (or otherwise causes a commit with a known sha to be tracked by the victim's Shipit stack).
2. Pushes/owns that exact commit in a repository they control (their fork), where they have push access and thus permission to create a commit status via the GitHub API.
3. GitHub delivers a legitimately signed `status` webhook whose `repository.full_name` is the attacker's own repo.
4. `verify_signature` passes (it only checks the signature matches the attacker's own org/app, which is correctly configured).
5. `StatusHandler#process` finds the `Commit` row belonging to the **victim's** stack (same sha, different `stack_id`) and rewrites its `Status` with a `context` in `stack.blocking_statuses` and `state: 'success'` (or a blocking failing state).
6. `Commit#blocked?` for a later, still-undeployed commit on the victim stack now flips, since the older sibling's `blocking?` result changed — even though the attacker never authenticated against the victim's repository.

No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, `force_github_authentication`) checks that the mutated `Commit`/`Stack` actually belongs to the authenticated repository for status events; the `stacks` scoping helper exists in the base `Handler` class specifically to prevent this, but `StatusHandler` bypasses it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Impact Explanation
An attacker can write a `Status` row against a `Commit` belonging to a stack/repository they never authenticated for, directly flipping `Commit#blocked?`/`Commit#deployable?` results for that victim stack. This can unblock continuous delivery (allowing an unintended deploy to proceed) or block it (denial of legitimate deploys) for a repository the attacker does not own. This matches the "Critical: a payload for one repository mutating another's stack, commit... or an unauthorized deploy" category, since `blocked?` feeds directly into `deployable?` (app/models/shipit/commit.rb:227-229) and the continuous-delivery pipeline.

### Likelihood Explanation
Preconditions: victim stack has `blocking_statuses` configured with multiple undeployed commits (explicitly stated as given); the attacker needs a repository under an organization already configured with a Shipit GitHub App (so `verify_signature` succeeds), and needs a `Commit` sha collision between their own repo and the victim's tracked stack — realistically achievable via forked PR commits/review stacks or shared upstream history. Attacker cost is low (one legitimate `status` API call on their own repo/commit); the flaw is fully repeatable against any sha collision they can produce.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing raw `Commit`/model lookups by sha) to the authenticated repository, e.g. replace `Commit.where(sha: params.sha)` with a lookup restricted to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`, mirroring the `stacks` helper already provided by `Webhooks::Handlers::Handler`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook from an unrelated repository cannot mutate another stack's commit" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack(repository: create_repository(owner: 'attacker-org', name: 'evil-repo'))

  shared_sha = 'deadbeef' * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  victim_stack.update!(cached_deploy_spec: deploy_spec_with(blocking_statuses: ['ci/blocking']))
  newer_commit = victim_stack.commits.create!(sha: 'cafebabe' * 5, ...)

  # baseline: before the forged status, newer_commit is not blocked by ci/blocking
  refute newer_commit.blocked?

  # forged payload: repository field names the attacker's own repo (so it passes verify_signature),
  # but sha collides with victim_commit
  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/blocking',
    'repository' => { 'full_name' => 'attacker-org/evil-repo', 'owner' => { 'login' => 'attacker-org' } },
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # broken binding: victim_commit's status changed even though payload authenticated for attacker-org/evil-repo
  assert victim_commit.reload.statuses.exists?(context: 'ci/blocking', state: 'success')
  assert newer_commit.blocked?, "newer_commit.blocked? flipped due to a status authenticated under a different repository"
end
```

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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
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
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
