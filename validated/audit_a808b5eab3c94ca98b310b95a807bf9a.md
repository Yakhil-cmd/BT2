### Title
Cross-repository commit-status forgery unblocks victim stack deploys - StatusHandler#process (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by SHA (`Commit.where(sha: params.sha)`), with no scoping to the repository that sent the webhook. Any GitHub `status` event whose signature validates for *some* organization can flip the CI status of a commit belonging to a completely different, unrelated stack if that stack happens to contain a commit with the same SHA, allowing an attacker to clear `Commit#blocked?` on a victim stack and enable an unauthorized deploy.

### Finding Description
The broken binding: `status.commit.stack_id == repository_that_produced(status.context/state)`. The code instead only enforces `status.commit.sha == params.sha`, dropping repository identity entirely.

Path:
- `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the HMAC signature via `verify_signature`, which resolves a `GithubApp` only by `repository_owner` (`params.dig('repository','owner','login')`) — it authenticates that *a* repository under that owner sent the event, not that the event's SHA belongs to *that* repository. [1](#0-0) 
- `Shipit::Webhooks::Handlers::Handler` provides a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)` using `payload.dig('repository','full_name')` — the correct pattern for tying an event to its own repo's stacks. [2](#0-1) 
- `StatusHandler#process` does **not** use this `stacks` scoping at all. It looks up commits globally by SHA and applies the status to every match: [3](#0-2) 
- `Commit#create_status_from_github!` then writes the status using the target commit's *own* `stack_id`, which is what makes the forged success "real" from the victim stack's perspective: [4](#0-3) 
- `Commit#blocked?` walks `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)`, and `Status::Common#blocking?` is `!success? && commit.blocking_statuses.include?(context)` — flipping the earlier commit's status to `success` for the blocking context removes it from the blocking set. [5](#0-4) [6](#0-5) 
- `Commit#deployable?` then reevaluates true for the later, previously-blocked commit. [7](#0-6) 

Exploit flow: an attacker who controls a repository whose commit history shares a SHA with a commit in the victim's stack (e.g., a public fork of the victim repository, so pre-fork commits share identical SHAs) sends/triggers a `status` webhook from their own repository (signed with a valid webhook secret for their own organization/app installation) naming the shared SHA and `state: success` with the victim stack's blocking context. Because `StatusHandler#process` never checks that the commit's stack matches the event's repository, the blocking commit in the victim's stack is marked successful, `blocked?` flips to `false` for later commits, and `Stack#next_commit_to_deploy` can pick and deploy a commit whose CI was never actually validated by the victim's own repository/CI system.

`verify_signature` and `drop_unhandled_event` only validate that the request came from a legitimate, signed GitHub webhook for *some* org — they provide no repository/stack binding check, so they do not prevent this divergence.

### Impact Explanation
A payload legitimately signed for one repository can mutate the CI/status state of an unrelated repository's stack, directly unblocking and enabling an unauthorized deploy on the victim stack — this matches the "Critical" category ("a payload for one repository mutating another's stack, commit, task or team... or an unauthorized deploy"). Blast radius: any Shipit instance hosting multiple stacks/repos where SHA collisions across repos are possible (most commonly via forks of the same repo, which is a normal and common GitHub workflow), is affected; the attacker does not need any privilege on the victim repository or stack.

### Likelihood Explanation
Preconditions: victim stack must have a non-empty `blocking_statuses` config and an undeployed commit chain with an earlier blocking commit; the attacker needs a repository whose commit history shares a SHA with a commit in the victim's stack (trivially achieved by forking the victim's public repo before the point of divergence) and the ability to have GitHub deliver a validly-signed `status` webhook for that repository/context to the shared Shipit webhook endpoint (e.g., by installing the same GitHub App on their own account/fork, or by any workflow that emits a status event on their fork). No Shipit session, API token, or secret is required. This is a low-cost, repeatable attack against any stack meeting the preconditions.

### Recommendation
Scope `StatusHandler#process` to the repository that sent the event, mirroring the base `Handler#stacks` pattern: resolve the commits via the stacks belonging to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (e.g., `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }`) rather than a global `Commit.where(sha: params.sha)`, so a status update can never be applied to a commit outside the sending repository's own stacks.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks/repositories, `victim/repo` and `attacker/repo`, each with a commit sharing the identical `sha` value (simulating a shared fork ancestor).
2. In `victim/repo`'s stack, configure `blocking_statuses` to include `ci/blocking`, create an earlier commit with a pending/failing `ci/blocking` status, and a later commit.
3. Assert `later_commit.blocked?` is `true` and `later_commit.deployable?` is `false` before the webhook.
4. Invoke `StatusHandler.call` with a payload whose `repository.full_name == "attacker/repo"` and `sha` equal to the shared SHA, `context: "ci/blocking"`, `state: "success"`.
5. Reload the victim commit/stack and assert `later_commit.blocked?` is now `false` and `later_commit.deployable?` is `true` — proving the binding `commit.stack == payload.repository` was never enforced and a foreign-repository payload flipped the victim stack's blocking state.
6. Fix validation: after patching `StatusHandler#process` to scope by `stacks`, rerun the same test and assert `later_commit.blocked?` remains `true` (status write is rejected/ignored because the SHA does not belong to `attacker/repo`'s stacks).

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
