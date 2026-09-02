### Title
Cross-repository `Status` write via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire installation and writes a `Status` to every matching `Commit`, without checking that the commit's stack belongs to the repository that authenticated the webhook. Because the webhook signature is verified only at the GitHub-organization/App level (not per-repository), any repository sharing that App installation can emit a `status` event that mutates a `Commit`/`Status` belonging to a completely different stack, including one for which `continuous_deployment` is enabled and `security/scan` is a required context.

### Finding Description
The broken binding is: it must hold that `payload.dig('repository','full_name') == commit.stack.repository.full_name` for every `Status` written from a webhook. In `StatusHandler`, this equality is never checked: [1](#0-0) 

Compare this to other handlers in the same module (`PushHandler`, `CheckSuiteHandler`), which scope their queries through `Handler#stacks`, itself derived from `payload.dig('repository','full_name')`: [2](#0-1) [3](#0-2) 

`StatusHandler` does not use `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` globally, then calls `commit.create_status_from_github!(params)` on every match, which creates a `Status` row and runs `add_status`, potentially firing `deployable_status` hooks and scheduling merges: [4](#0-3) [5](#0-4) 

The `WebhooksController#verify_signature` guard only checks the request signature against `Shipit.github(organization: repository_owner)`, i.e. the GitHub App/organization-level `webhook_secret`, not a per-repository secret: [6](#0-5) [7](#0-6) 

Since one GitHub App installation/webhook secret typically covers every repository under an organization, a `status` event legitimately signed for repository A (any repo in the org an attacker can push commits to) is fully valid at the controller level even when it targets a `Commit` that only exists in Stack B's (a different repository's) history. Git commit SHAs are content-addressed, not repository-scoped: an attacker who can see or copy a victim commit's tree/parents/author data (e.g., a public commit, PR, or fork) can push an identical commit (same SHA) to their own repository in the same org, then have GitHub emit a `status` webhook — signed with the shared org secret — with `context: security/scan`, `state: failure`, for that SHA. `StatusHandler#process` will apply this status to any `Commit` row in the database with that SHA, including the one belonging to the victim's stack, without any repository-identity check.

If the victim stack has `continuous_deployment` enabled and treats `security/scan` as a required/blocking context, the forged `failure` (or conversely a forged `success`) flips `previous_status.simple_state != new_status.simple_state`, firing `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` — driving the stack's continuous-delivery machinery (`ContinuousDeliveryJob`) to either block a legitimate deploy or, on a forged `success`, allow one to proceed, independent of the actual CI/security-scan result for that repository.

None of the listed guards prevent this: `verify_signature` only authenticates "some repo in this org sent this", `drop_unhandled_event` only checks the event type is registered, the `ExplicitParameters` schema in `StatusHandler` only validates shape (`sha`, `state`, `context`, etc.) not repository ownership, and there is no `force_github_authentication`/`require_permission!`/`stacks` scope check in this handler at all.

### Impact Explanation
A forged `status` webhook write a `Status` record for a `Commit` belonging to a stack/repository that never authenticated it. On a victim stack with `continuous_deployment` enabled, this can force an unauthorized ship (spoofed `success` on a required context) or an unauthorized block/rollback (spoofed `failure`, e.g. against `security/scan`), matching the Critical category "a payload for one repository mutating another's stack, commit... or an unauthorized deploy, rollback". The blast radius spans every stack in the same GitHub App installation (typically an entire GitHub organization) that happens to have a `Commit` row with the colliding SHA — repeatable against any stack for which the attacker can reproduce/copy the target SHA.

### Likelihood Explanation
Preconditions: attacker needs push access to some repository under the same GitHub organization/App installation as the victim stack (common in orgs with many repos, public orgs, or orgs allowing member-created repos), and the ability to reproduce a commit object with the exact target SHA (feasible for public commits/PRs by copying the commit into their own repo). No Shipit secrets, session, or API token are required — GitHub itself signs the webhook for the attacker's own repository. The attack is repeatable at will for any SHA the attacker can duplicate.

### Recommendation
Scope `StatusHandler#process` to the reporting repository, mirroring `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` (or otherwise derive the repository from the payload) and restrict the `Commit` lookup to commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or extend `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks `stack_a` (repo `attacker/repo`) and `stack_b` (repo `victim/repo`), both resolvable under the same organization login (e.g. `shopify`) so `verify_signature` passes for both.
2. Create a `Commit` with the same `sha` value under both `stack_a` and `stack_b` (simulating a duplicated commit object). Configure `stack_b` with `continuous_deployment` enabled and `security/scan` as a required status context.
3. Build a `status` payload with `repository.full_name = 'attacker/repo'`, `sha` matching the shared SHA, `context: 'security/scan'`, `state: 'failure'`, and POST it to `/webhooks` with the `X-Github-Event: status` header.
4. Assert the binding before: `stack_b.commits.find_by(sha: sha).statuses.where(context: 'security/scan').none?` and record `stack_b.commits.find_by(sha: sha).deployable?` (true, matching required context absent/success).
5. After posting, assert the binding is broken: `stack_b.commits.find_by(sha: sha).statuses.where(context: 'security/scan', state: 'failure').exists?` is `true`, and `stack_b.commits.find_by(sha: sha).deployable?` (or `.locked?`/schedule_merges effect) has flipped — even though the webhook's `repository.full_name` was `attacker/repo`, not `victim/repo`. This demonstrates `payload.dig('repository','full_name') != commit.stack.repository.full_name` while the write still succeeded.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
