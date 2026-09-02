### Title
Cross-tenant Commit/Status mutation via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` never calls `Handler#stacks`, so it never checks that the webhook's `repository.full_name` corresponds to a tracked `Shipit::Repository`. It instead runs `Commit.where(sha: params.sha)` against the entire `commits` table and mutates every matching row's statuses, regardless of which repository (or organization) the webhook actually came from.

### Finding Description
The claimed binding is: `stacks` (the set of stacks the webhook payload's `repository.full_name` authorizes via `Repository.from_github_repo_name(repository_name)&.stacks`) `==` the actual set of stacks whose `Commit` rows get mutated by the handler.

`Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-34) resolves this authorized set and defaults to `Stack.none` when the repository isn't tracked: [1](#0-0) 

`StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) never references `stacks`/`repository_name` at all: [2](#0-1) 

Instead it does a **global, unscoped** lookup by SHA across the whole `commits` table and calls `commit.create_status_from_github!(params)` for every match, which appends a new row to that commit's `statuses` association and can flip the commit's computed `status`/`deployable?` state: [3](#0-2) [4](#0-3) 

The only gate before this handler runs is `WebhooksController#verify_signature`, which authenticates the request against `Shipit.github(organization: repository_owner)` — i.e. it authenticates the *organization/App installation*, not the specific *repository*: [5](#0-4) 

Because a GitHub App/webhook secret is configured per organization (not per repository), any repository the attacker controls under an org that already has Shipit configured — or any repository whose owner login happens to already be a configured "GitHub organization" in Shipit — can produce a validly-signed `status` event even though that specific `repository.full_name` was never registered as a `Shipit::Repository`. `drop_unhandled_event` doesn't help since `status` is a handled event, and `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not repository ownership.

Exploit flow:
1. Attacker owns/pushes to a repository under an org where Shipit's GitHub App is installed (satisfying "webhook from a repository they own" per the rules), but that repository is never added to Shipit as a `Repository`/`Stack`.
2. Attacker learns (or guesses/enumerates) the SHA of a commit tracked by a legitimate, unrelated Shipit stack (SHAs are frequently public via the target repo's own commit history or the Shipit UI).
3. Attacker POSTs a `status` webhook event to `/webhooks` with `repository.full_name` = their own untracked repo and `sha` = the victim commit's SHA, `state: "success"`.
4. `verify_signature` passes (org-level secret, not repo-level). `StatusHandler#process` finds the victim `Commit` row by SHA (ignoring `repository_name`) and calls `create_status_from_github!`, appending a forged status to the victim stack's commit and potentially unblocking deploy/merge gating (`deployable?`, `blocked?`) for a stack the attacker never authenticated against.

This breaks the equality: the authorized set (`stacks` for the attacker's untracked repo, which would be `Stack.none`) is empty, while the actually-mutated set includes the real stack owning the SHA-colliding commit.

### Impact Explanation
A webhook whose repository is not tracked by Shipit at all can write `Status`/`Commit` state belonging to a different tenant's stack, directly matching the listed Critical category "a payload for one repository mutating another's stack, commit, task or team." Because commit `status`/`deployable?` gates continuous deployment (`schedule_continuous_delivery`, `blocked?`, `deployable?`), forging a passing status can influence whether an unrelated stack proceeds with an unauthorized deploy — compounding into "an unauthorized deploy." The attack is trivially repeatable against any SHA the attacker can learn, across any number of tracked stacks that happen to share that SHA (e.g., forks/mirrors, or in the pathological case, colliding commit content across repos).

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository that can deliver a validly-signed webhook to the Shipit host's `/webhooks` endpoint (i.e., it sits under an org/App installation already configured in Shipit) but is itself not registered as a `Shipit::Repository`. This is a realistic setup in any multi-repo GitHub organization where only some repos are onboarded to Shipit while the GitHub App is installed org-wide. The attacker needs no Shipit credentials, session, or API token — only knowledge of a target commit SHA, which is often public. Cost is a single unauthenticated (from Shipit's perspective) HTTP POST.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stacks authorized by the payload's repository, e.g. `stacks.flat_map(&:commits).find_by(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring the pattern other handlers use with `Handler#stacks`, and no-op when `stacks` is empty (`Stack.none`).

### Proof of Concept
Minitest plan (under `test/models/shipit/webhooks/handlers/status_handler_test.rb`, not shown/executed here since `test/**` is out of scope for this audit but described for reproduction):
1. Create a tracked `Stack`/`Repository` (`victim/repo`) and a `Commit` with `sha: "a" * 40` belonging to it.
2. Build a `status` webhook payload with `repository.full_name = "attacker/repo"` (no matching `Shipit::Repository` record exists) and `sha: "a" * 40`, `state: "success"`.
3. Assert before: `victim_commit.statuses.count == 0` and `Repository.from_github_repo_name("attacker/repo")` is `nil` (so `Handler#stacks` for this payload would resolve to `Stack.none`).
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert after: `victim_commit.reload.statuses.count == 1`, proving a payload whose authorized `stacks` set is empty mutated a `Commit` belonging to the victim stack — confirming the broken binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
