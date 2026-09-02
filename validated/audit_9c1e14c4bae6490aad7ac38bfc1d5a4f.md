### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike sibling handlers such as `PushHandler` which correctly use the repository-scoped `stacks` helper. Any commit that exists with the same SHA under a different stack (e.g. a shared/forked history commit) will have its CI status mutated by a webhook that was only ever authenticated for the attacker's own repository.

### Finding Description
The broken binding is: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')`. This should always hold for any commit whose status is being written, but `StatusHandler#process` never checks it.

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Compare with the base `Handler` class, which provides a repository-scoped accessor (`stacks`) built from `payload.dig('repository', 'full_name')`: [2](#0-1) 

And `PushHandler`, which correctly uses that scope before touching any stack: [3](#0-2) 

`StatusHandler` ignores `stacks`/`repository_name` entirely and queries `Commit` globally by SHA, then calls `commit.create_status_from_github!(params)`, which writes a `Status` row and re-evaluates `deployable?`/`blocked?`/continuous-delivery scheduling for whatever stack that commit belongs to: [4](#0-3) [5](#0-4) 

`verify_signature` in `WebhooksController` only proves that the payload was sent by the GitHub App belonging to `repository_owner` (the payload's own `repository.owner.login`); it says nothing about which `Commit` rows the handler is allowed to touch: [6](#0-5) 

Exploit flow: the attacker owns/controls a repository that is legitimately onboarded to Shipit (so their GitHub App/webhook secret validates), and there exists a victim `Stack`/`Commit` whose `sha` collides with a commit SHA the attacker can produce a `status` webhook for (e.g., a shared upstream commit that exists identically in both the attacker's fork and the victim's tracked repository — a very common occurrence for shared base commits, not a full SHA-1 preimage attack). The attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid signature for their own org, and body `{ "sha": "<shared sha>", "state": "failure", "context": "continuous-integration/travis-ci", "repository": {"full_name": "attacker/repo", ...} }`. `StatusHandler#process` finds `Commit.where(sha: params.sha)` and this returns the victim's `Commit` too (since the query has no repository/stack filter), and `create_status_from_github!` writes a `failure` status onto it, flipping `deployable?`/`blocked?` for the victim stack. This can block/unblock deploys, or (per `add_status`) trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges`.

None of the existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) check that the resolved `Commit#stack` belongs to the repository named in the payload, so the divergence is real and exploitable.

### Impact Explanation
An attacker who controls any repository onboarded to Shipit can, by sending a legitimately-signed `status` webhook for their own repository, mutate the CI status of a `Commit` belonging to an unrelated victim `Stack`, as long as the SHA is shared between the two histories (common for forks/shared upstream commits). This can force a required-status check to `failure`, blocking deploys/merges, or clear it to `success`, unblocking a deploy that should have been gated — a cross-tenant state write not authenticated by the affected repository, matching the Critical "payload for one repository mutating another's stack/commit" category.

### Likelihood Explanation
Preconditions: the attacker needs their own repository already connected to Shipit (so `verify_signature` passes for their organization) and a commit SHA shared with a victim's tracked history — realistic for forks of the same upstream project or repos mirroring a common base branch. No privileged Shipit role, session, or secret is required. The attack is fully repeatable and requires only a single crafted HTTP POST per SHA collision found.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository that authenticated the webhook, analogous to `PushHandler`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }`, before calling `create_status_from_github!`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_a` (victim) with `repository.full_name = "victim/repo"` and a required status `continuous-integration/travis-ci`; create `commit = shipit_commits(:...)` with `sha = "abc123..."` under `stack_a`.
2. Create `stack_b` (attacker) with `repository.full_name = "attacker/repo"`, and a `Commit` under `stack_b` with the same `sha = "abc123..."`.
3. Assert baseline: `commit.reload.deployable?` is `true` (or whatever pre-status state) — i.e. `stack_a`'s commit status is unaffected by `stack_b`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call('sha' => 'abc123...', 'state' => 'failure', 'context' => 'continuous-integration/travis-ci', 'repository' => { 'full_name' => 'attacker/repo' })`.
5. Assert `commit.reload.deployable?` changed to `false` (or `blocked?` becomes `true`) even though the payload's `repository.full_name` was `attacker/repo`, proving the victim `stack_a` commit was mutated by a webhook that never authenticated for `victim/repo`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
