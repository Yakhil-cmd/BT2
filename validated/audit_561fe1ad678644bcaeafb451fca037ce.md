### Title
StatusHandler#process mutates commits across arbitrary stacks by matching `sha` alone, bypassing repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, with no repository/stack scoping at all, unlike every other handler which derives its target rows from `Handler#stacks` (itself scoped via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`). Any signed 'status' webhook for a repository whose commit sha happens to also exist in another Stack's `commits` table will write a `Status` row into that unrelated Stack.

### Finding Description
The binding that should hold, matching every other handler in `app/models/shipit/webhooks/handlers/`, is:

`mutated_commits.map(&:stack_id) ⊆ Handler#stacks(payload.repository.full_name).map(&:id)`

`Handler#stacks` is defined as: [1](#0-0) 

Every other handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) derives its target `Stack`/`ReviewStack` from `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, e.g.: [2](#0-1) 

`StatusHandler#process`, however, never calls `stacks` or resolves `params.repository` at all — it queries `Commit` globally by `sha` and mutates every matching row: [3](#0-2) 

That call reaches `Commit#create_status_from_github!`, which replicates a `Status` into `statuses` scoped by `stack_id`, and fires stack-level hooks/jobs (`deployable_status`, `ProcessMergeRequestsJob`) once the transition rules match: [4](#0-3) 

**Verification of guards**: `WebhooksController#verify_signature` authenticates the webhook using `Shipit.github(organization: repository_owner).verify_webhook_signature`, keyed off `params.dig('repository', 'owner', 'login')`: [5](#0-4) 

This only proves the payload was genuinely emitted by GitHub for the attacker's own organization/repository — it says nothing about which `sha` value is inside that payload. GitHub does not prevent an attacker from setting a commit status (via a real `status` webhook GitHub fires for their own repo) referencing any `sha` string of their choosing (GitHub validates the `sha` exists in *their* repo, not that it's unique across Shipit's whole install). So the signature check is orthogonal to the missing repository-scoping bug; it does not block the exploit.

**Exploit flow**: 
1. Attacker's own repo `attacker/lowtraffic` is a Shipit-tracked repo (precondition, stated as given).
2. Attacker reads target stack's commit shas via Shipit's public dashboard/API (or otherwise obtains/engineers a sha that already exists as a `Commit` row for an unrelated Stack, e.g. via forked/shared git history, monorepo split, or repository migration where old `Commit` rows persist under a different `Stack`).
3. Attacker pushes a commit to their own repo and gets GitHub to fire (or crafts, using their real, valid webhook secret for their own org) a `status` event with `sha` equal to that value and `state: 'error'`.
4. `WebhooksController#verify_signature` passes because the payload is a genuine signed webhook for the attacker's organization.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — this matches the `Commit` row belonging to the victim's unrelated Stack (not the attacker's own commit, which may not even exist as a `Commit` record if never synced) — and calls `create_status_from_github!`, writing an `error` status into the victim's Stack, potentially blocking deploys/merges via `deployable_status`/`ProcessMergeRequestsJob` side effects.

### Impact Explanation
A cross-repository write: an attacker-controlled, legitimately-signed webhook for their own repository injects a `Status` row (and downstream hook/job side effects) into a `Commit`/`Stack` belonging to a completely different, unrelated tenant, without ever having interacted with that tenant's repository. This matches the "Critical" category explicitly listed: *"a payload for one repository mutating another's stack, commit, task or team."* The blast radius spans every Stack across the entire Shipit installation that happens to share a `sha` with the attacker-chosen value, and is repeatable per request for any sha the attacker can enumerate via the public dashboard/API.

### Likelihood Explanation
The attacker needs: (a) control of at least one Shipit-tracked repository (a stated precondition), and (b) a `sha` value that already exists as a `Commit` row under a different Stack. Because commit shas are content-addressed, exact collision across genuinely unrelated repositories is not the realistic path; the realistic path is shared history — forks, mirrors, monorepo splits, or Stack/Repository re-configuration — where the identical commit legitimately exists under multiple `Stack` rows. In such (common) setups, exploitation costs the attacker nothing beyond reading public commit shas and sending one webhook; it is fully repeatable.

### Recommendation
Scope `StatusHandler#process` through `Handler#stacks` / the verified payload's repository, exactly like every other handler, e.g. restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or join `Commit` to `Stack` via `repository_id` derived from `params.repository.full_name`) so only commits within stacks belonging to the authenticated repository can be mutated.

### Proof of Concept
Minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb`:
1. Create two Stacks, `victim_stack` (repo `victim/repo`) and `attacker_stack` (repo `attacker/repo`), each with a `Commit` sharing the same `sha`.
2. Stub/spy `StatusHandler#stacks` (e.g. `Shipit::Webhooks::Handlers::StatusHandler.any_instance.expects(:stacks).never`) to prove the base-class repository-scoping method is never invoked.
3. Build a `status` payload whose `repository.full_name == 'attacker/repo'` and `sha` equal to the shared sha, `state: 'error'`.
4. Call `StatusHandler.call(payload)`.
5. Assert `victim_stack.commits.find_by(sha: sha).statuses.last.state == 'error'` — i.e., the victim's unrelated stack was mutated by a payload authenticated only for `attacker/repo`, proving `mutated_commits.map(&:stack_id)` is **not** a subset of `Handler#stacks('attacker/repo').map(&:id)`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
