### Title
`StatusHandler#process` writes cross-repository `Status` rows via unscoped `Commit.where(sha:)` lookup, flipping `Stack#deployable?` without repo binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Webhooks::Handlers::StatusHandler#process` resolves target commits by `sha` alone, with no scoping to the repository that emitted the webhook, even though the base `Handler` class already provides a `stacks`/`repository_name` helper for exactly this purpose that every other handler uses. A validly-signed `status` webhook for repository A therefore can write a `Status` row (with `stack_id` taken from whatever `Commit` matches that sha) against a completely unrelated stack B, which is sufficient to flip `Commit#deployable?` and `Stack#deployable?` and fire `Stack#trigger_continuous_delivery`.

### Finding Description
The broken binding is: **"a `Status` scoped to `stack` B"** should require **"a signed webhook whose `repository.full_name` corresponds to stack B's repository"**, but the code instead accepts **"a signed webhook from any repository, as long as the reported `sha` happens to match a `Commit` row belonging to stack B."**

- `StatusHandler#process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
This is a global, unscoped query against the `commits` table — it never consults `payload.dig('repository', 'full_name')`.

- The base `Handler` class already exposes the correct scoping primitive (`stacks`, derived from `Repository.from_github_repo_name(repository_name)`), used by other handlers, but `StatusHandler` does not call it at all: [2](#0-1) 

- `Commit#create_status_from_github!` writes the `Status` with `stack_id` taken from the matched commit's own `stack_id`, not from the reporting repository: [3](#0-2) 

- `Status#after_create`/`after_commit` callbacks unconditionally enable CI and schedule continuous delivery for the commit's stack, regardless of which repository actually authenticated the webhook: [4](#0-3) 

- `Commit#deployable?` only requires `!locked? && (stack.ignore_ci? || (success? && !blocked?))` — with `ignore_ci? == false`, a single `success` `Status` row (with no blocking statuses and no lock) is sufficient: [5](#0-4) 

- The controller-level signature check (`verify_signature`) only proves the payload was signed by *some* organization derived from the payload's own `repository.owner.login` field — it never ties that organization/repository back to the stack whose commit ends up receiving the `Status`: [6](#0-5) 

**Exploit flow:** attacker legitimately owns/administers a repository A that is onboarded to this Shipit instance (satisfies "any GitHub user who can ... emit webhooks from a repository they own"). GitHub genuinely and correctly signs a `status` event for repo A. Attacker sets the `sha` field to a commit SHA that they know belongs to victim stack B (trivially knowable if B's repo is public, or discoverable through Shipit's own UI/API for the target stack) and `state: success`. `StatusHandler#process` matches that SHA against `Commit` rows system-wide, finds stack B's commit, and creates a `Status` with `stack_id: B`. This satisfies `commit.success?`, and if `blocked?` is false and the commit isn't locked, `deployable?` becomes true and continuous delivery on stack B is scheduled/triggered — despite the webhook never having authenticated for repository B.

Existing guards do not close this: `verify_signature` authenticates only the reporting organization/repository (A), not the target stack (B); `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not repo-stack binding; there is no `blocked?` override or lock requirement that would stop this in the `ignore_ci? == false` path.

### Impact Explanation
A repository that authenticated only for itself (A) can cause an unauthorized `Status`/deploy trigger against an unrelated stack B, matching the "payload for one repository mutating another's stack ... or an unauthorized deploy" Critical category. Repeatable against any stack whose commit SHAs are known to the attacker (trivial for public repos, or any repo the attacker can otherwise observe), for as many target stacks/SHAs as the attacker cares to enumerate, from a single onboarded repository they control.

### Likelihood Explanation
Requires: (1) the attacker legitimately controls at least one repository/organization already onboarded to the target Shipit instance (multi-tenant deployments of Shipit are common), (2) the attacker knows a commit SHA present in the victim stack's `commits` table (trivial for public repos, or via any stack's visible history), (3) the victim stack has `ignore_ci? == false`, no blocking statuses, and the target commit unlocked (the default configuration). No secrets, sessions, or privileged roles are required beyond ordinary control of one's own onboarded repository — the signature is genuinely valid for that repository, the flaw is purely in `StatusHandler` failing to bind the write to that repository's own stacks.

### Recommendation
Scope `StatusHandler#process` to the stacks derived from the webhook's own `repository.full_name`, mirroring the `stacks` helper already defined in `Handler`, e.g. restrict the lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (model/controller-level, no live GitHub, following the existing pattern of stubbing `verify_signature`, e.g. `GithubHook.any_instance.stubs(:verify_signature).returns(true)` as used in `test/controllers/webhooks_controller_test.rb`):

1. Create `stack_a` (repository "attacker/repo-a") and `stack_b` (repository "victim/repo-b") with distinct `Repository`/`Stack` records.
2. Create `commit_b` under `stack_b` with a known `sha` (e.g. `"deadbeef" * 5`), no prior `Status` rows, `commit_b.locked? == false`.
3. Assert precondition: `stack_b.ignore_ci? == false`, `commit_b.blocked? == false`, `commit_b.deployable? == false` (no Status yet).
4. POST to `/webhooks` with `X-Github-Event: status`, body `{ sha: commit_b.sha, state: "success", repository: { full_name: "attacker/repo-a", owner: { login: "attacker" } } }`, with `verify_signature` stubbed true (simulating a genuinely valid signature for repo A only).
5. Assert a `Status` row was created with `stack_id: stack_b.id` even though the webhook's `repository.full_name` was `"attacker/repo-a"`.
6. Assert `commit_b.reload.deployable?` is now `true`.
7. Assert `stack_b.trigger_continuous_delivery` fires a deploy (`assert_difference('Deploy.count', 1) { stack_b.trigger_continuous_delivery }` or assert the job enqueued via `Status`'s `schedule_continuous_delivery` callback).

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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
