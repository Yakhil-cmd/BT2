### Title
`StatusHandler#process` writes GitHub status updates to any `Commit` matching `sha` across the entire Shipit installation, with no verification that the reporting repository matches the commit's owning `Stack`/repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target records purely by `Commit.where(sha: params.sha)`, with no comparison against the webhook payload's `repository.full_name`/`repository_owner`. `Status` model validation (`validates :state, inclusion: { in: STATES }`) only restricts *which* state strings are legal, it never restricts *which repository* may set them. As a result, any of the four legal states (`pending`, `success`, `failure`, `error`) can be written cross-repository as long as the attacker can get a signature-verified webhook delivered for *some* organization/repo they control that happens to reference a `sha` shared with a victim commit.

### Finding Description
The claimed binding is: `repository authorizing the state change == repository of the commit whose status/merge state is mutated`. Tracing the code shows this binding is never enforced:

- `WebhooksController#verify_signature` only checks that the payload's HMAC signature matches the GitHub App secret for `repository_owner = params.dig('repository','owner','login')`. This proves the payload came from *some* GitHub org/repo whose secret validated, not that it came from the org/repo owning the target commit. [1](#0-0) 
- `StatusHandler#process` then does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` - a global lookup by `sha` alone, with zero reference to `params['repository']` at all. [2](#0-1) 
- `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)`, using the **victim commit's own `stack_id`**, not anything derived from the attacker's payload. [3](#0-2) 
- `Status.replicate_from_github!` accepts whatever `state` string is present (validated only against `STATES`, not against repository identity) and persists it. [4](#0-3) 
- `add_status` recomputes `status`/`deployable?` and calls `stack.schedule_merges` on success/pending transitions, and the commit's `deployable?`/`blocked?` state (used by `MergeRequest#any_status_checks_failed?`/`reject!`) is derived purely from the newly-written `Status` rows, again with no repository check. [5](#0-4) [6](#0-5) 

Because git SHAs are content-addressed, an attacker who forks the victim's repository (or otherwise produces an identical commit object, e.g. by branching from the same parent with no changes) shares the exact same `sha` for that commit between their fork and the victim's repo/PR head. If the attacker's own repo/org is already onboarded to the same Shipit instance (has its own valid webhook secret), a `status` webhook fired from the attacker's own repo will pass `verify_signature` (since it is validated against the attacker's own org/secret) and then match and mutate the **victim's** `Commit` row purely via the shared `sha`, with **any** state value - `failure` to sabotage, or `success`/`pending` to falsely mark it green or force `schedule_merges`.

To directly answer the question: the handler does **not** enforce "state must be legal AND repository must match" as a conjunction - there is no repository-matching check at all in this write path, at any layer (controller, handler, or model). So this is not limited to `state: 'success'`; every accepted state value is equally cross-repo writable, including `failure` used to sabotage a competitor's green commit and block `deployable?`/`allows_merges?`/trigger `MergeRequest#reject!('ci_failing')` via `any_status_checks_failed?`.

### Impact Explanation
An attacker who controls a repository/fork already onboarded to a shared Shipit instance can silently flip the CI status of another tenant's commit that happens to share a `sha` (typical for fork/PR head commits), causing:
- False `failure`/`error` status → victim's `deployable?` becomes `false`, blocking deploys and causing `MergeRequest#reject!('ci_failing')` to fire, sabotaging a competitor's pending merge.
- False `success`/`pending` → could mask real CI failures or trigger `stack.schedule_merges`, an unauthorized merge-relevant state change.

This is a cross-tenant, cross-repository mutation of another party's `Commit`/`Status`/`MergeRequest` state with no attacker privilege on the victim's stack, matching the "payload for one repository mutating another's stack, commit, task or team" Critical category. It is repeatable against any commit sha the attacker can reproduce and any Shipit tenant sharing the instance.

### Likelihood Explanation
Preconditions: the attacker must control a repository already onboarded as a Shipit stack (or in an org with a valid GitHub App installation/webhook secret recognized by this Shipit instance), and must be able to produce a commit with an identical SHA to the victim's target commit (trivially achievable via forking the victim repo prior to any diverging commits, or matching a shared ancestor commit). No GitHub team membership, Shipit session, or victim-repo webhook secret is required. This is realistic in any multi-tenant/enterprise Shipit deployment where multiple unrelated teams' repositories share one Shipit instance.

### Recommendation
`StatusHandler#process` (and analogous handlers like `CheckRunHandler` if they share this pattern) must scope the `Commit` lookup to the stack(s) whose `github_repo_name`/repository matches `params.dig('repository', 'full_name')` (or the `repository_owner`/`repository_id` from the payload), e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: matching_repository.id })`, rejecting/ignoring records for commits belonging to a different repository than the one that authenticated the webhook.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create two `Repository`/`Stack` records: `victim_stack` (repo `victim/app`) and `attacker_stack` (repo `attacker/app-fork`).
2. Create a `Commit` with `sha: 'deadbeef...'` under `victim_stack`, give it a `success` `Status`, and an open `MergeRequest` in `pending` state referencing that commit's PR head sha.
3. Also create a `Commit` with the same `sha` under `attacker_stack` (simulating the shared fork commit).
4. Build a status webhook payload: `{ sha: 'deadbeef...', state: 'failure', repository: { full_name: 'attacker/app-fork', owner: { login: 'attacker' } } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)` (bypassing `verify_signature`, simulating that it validated against attacker's own org secret).
6. Assert: `victim_stack.commits.find_by(sha: 'deadbeef...').status.state == 'failure'` (broken binding demonstrated - attacker's own-repo-authenticated payload mutated victim's commit).
7. Assert: victim's `MergeRequest.reload.state == 'rejected'` and `rejection_reason == 'ci_failing'`, proving unauthorized cross-tenant merge rejection.
8. Assert both sides of the intended binding never held: `payload[:repository][:full_name] != victim_stack.repository.full_name`, yet the write still succeeded.

### Citations

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

**File:** app/models/shipit/status.rb (L16-33)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

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
```
