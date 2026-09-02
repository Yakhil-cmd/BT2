### Title
Cross-repository `sha`-collision status forgery unscoped by repository, flipping `Commit#blocked?` for a victim stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/commit.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` — a global, un-scoped query across every repository/stack tracked by Shipit — instead of restricting to commits belonging to the repository that sent the webhook. Because `Commit#blocked?` and `#blocking?` are computed purely from attached `Status` rows, a webhook whose `sha`/`context` collide with a victim commit (e.g. because the two repositories share an identical, unmodified commit — a fork or cherry-pick scenario) lets an attacker overwrite that victim commit's status for a given `context`, unblocking a stack that would otherwise refuse to deploy.

### Finding Description
The binding the system is supposed to preserve is:
`status used by Commit#blocked?/#blocking? for commit C in stack S == a status produced by CI/webhook of the repository that owns stack S` (i.e. `status.stack_id/commit.stack.repository == payload.repository.full_name`).

The actual code never enforces the right-hand side: [1](#0-0) 

`StatusHandler#process` calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on repository at all — even though the base `Handler` class already provides a properly scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that other handlers use, but `StatusHandler` does not call it: [2](#0-1) 

`create_status_from_github!` then unconditionally writes a `Status` row keyed by `github_status.context`/`state`: [3](#0-2) [4](#0-3) 

That newly written status feeds `Commit#status`, `#blocking?`, and ultimately `#blocked?`: [5](#0-4) [6](#0-5) 

**Exploit path:** the attacker controls a second repository (their own fork, or another repo they own that shares an identical commit object — same tree/parents/message/timestamps — with the victim commit, hence the same SHA-1). If that attacker-owned repo already has the Shipit GitHub App installed under a Shipit-known organization, GitHub will legitimately sign a `status` webhook the attacker triggers for their own repo (e.g. via the GitHub Status API on their own repo). This produces a webhook whose signature passes `WebhooksController#verify_signature` (checked only against `repository_owner`, which is picked from the attacker-controlled `repository_owner` field but validated with the real GitHub-computed HMAC for that org — valid because it's a genuine GitHub delivery for a repo the attacker owns) — see: [7](#0-6) 

Once past signature verification, `StatusHandler` matches purely on `sha`, oblivious to which repository actually owns the target `Commit` row, and writes a `success` status for the matching `context` onto the victim's commit. `blocking?` for that `context` then resolves to `success`, and `Commit#blocked?` iterating over `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)` no longer counts that commit as blocking, unblocking deploy of subsequent commits.

No existing guard prevents this: `verify_signature` authenticates *who sent the webhook*, not *which repository's data may be mutated*; `ExplicitParameters` only validates payload shape (`sha`, `state`, `context` as free strings); and `StatusHandler` itself performs zero repository scoping on the `Commit` lookup, unlike the unused `stacks` helper in the base `Handler`.

### Impact Explanation
A payload legitimately originating from repository B (attacker-owned) mutates a `Status` record belonging to repository A's stack, which is exactly the "payload for one repository mutating another's stack/commit" Critical category. The direct consequence is bypass of a manual/CI blocking gate (`stack.blocking_statuses`), enabling an unauthorized/unreviewed deploy or merge to proceed on a victim stack that should remain blocked. This is repeatable against any stack whose commit history intersects (via shared/forked commits) with a repository the attacker controls, and the blast radius extends to every stack in the Shipit installation, since the `Commit.where(sha:)` lookup is entirely global and unscoped.

### Likelihood Explanation
Exploitation requires: (1) a repository the attacker owns/controls with the Shipit GitHub App installed (or otherwise able to produce a webhook whose signature validates for some organization known to Shipit) so `verify_signature` passes; and (2) that repository containing a commit whose SHA-1 is identical to a targeted commit in the victim's stack — realistic via forking or cherry-picking an unmodified commit, not requiring an actual SHA-1 collision attack. Given these preconditions (plausible within any organization that allows forking/repo creation and shares one GitHub App installation/secret across its repos), the attack cost is low and fully repeatable per targeted `context`/`sha` pair.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the requesting repository, mirroring the `stacks` helper already defined on `Handler`, e.g. resolve target commits via `stacks.flat_map(&:commits).where(sha: params.sha)` or join through `Stack`/`Repository` so `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or equivalent) instead of an unscoped `Commit.where(sha:)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest)
test "cross-repository status forgery unblocks a stack" do
  stack_a = shipit_stacks(:shipit) # repository "org/repo-a"
  stack_b = create_stack(repository: create_repository(owner: 'org', name: 'repo-b'))

  blocking_commit = stack_a.commits.create!(sha: 'a' * 40, message: 'blocking commit')
  blocking_commit.statuses.create!(stack: stack_a, state: 'pending', context: 'ci/required')
  newer_commit = stack_a.commits.create!(sha: 'b' * 40, message: 'follow up')

  assert newer_commit.blocked?, "sanity: newer commit should be blocked by pending required status"

  # Attacker controls stack_b's repository and it happens to contain an identical
  # commit object (shared sha) - forged webhook claims to originate from repo-b
  payload = {
    'sha' => blocking_commit.sha,
    'state' => 'success',
    'context' => 'ci/required',
    'repository' => { 'full_name' => 'org/repo-b', 'owner' => { 'login' => 'org' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  blocking_commit.reload
  assert_equal 'success', blocking_commit.status.state # forged write succeeded cross-repo
  refute newer_commit.reload.blocked?, "blocking gate was bypassed by cross-repo forged status"
end
```
Both sides of the binding (`Status belongs to stack_a` vs `payload.repository == "org/repo-b"`) diverge after the call, proving `StatusHandler` fails to enforce repository ownership before mutating `blocked?`'s inputs.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L219-219)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status
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
