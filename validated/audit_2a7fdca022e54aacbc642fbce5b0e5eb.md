### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` enables unauthorized merge/deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The Aragon report describes a voting system that authenticates *who may cast a vote* but never binds the vote's payload to the specific proposal it is supposed to affect, letting an attacker who controls any voting slot manipulate outcomes for votes they have no real standing in. The same class of bug exists in Shipit's `status` webhook handling: GitHub's webhook signature only proves *which organization/repository* originated the event, but `StatusHandler` never re-checks that binding when writing the status — it looks up commits by raw SHA across the entire Shipit database. An attacker with write access to any single low-privilege repository under an onboarded GitHub organization can therefore inject a fabricated "success" status onto a commit belonging to a completely different, higher-trust stack in the same organization, satisfying required CI checks and triggering an unauthorized merge or deploy.

### Finding Description
Webhook authentication in `WebhooksController#verify_signature` is performed at the **organization** level only: it resolves the app/secret via `Shipit.github(organization: repository_owner)` and validates the HMAC signature of the raw payload against that shared secret. [1](#0-0) 

This proves only "this payload was signed with organization O's webhook secret" — it says nothing about which *repository* within that organization the event concerns. GitHub computes and delivers this signature identically for a `status` event fired from **any** repository under that installation, including a repository the attacker fully controls (e.g., a sandbox repo they were added to as a collaborator, or their own fork with a configured webhook), since commit-status API calls can be made by anyone with push access to that one repo and can name any SHA1 string, not necessarily one that exists in that repo.

Most webhook handlers correctly re-derive the target scope from the payload's own `repository.full_name` before touching any records, via the shared `stacks` helper: [2](#0-1) 

`StatusHandler`, however, does not use this scoping. It looks up commits purely by SHA, instance-wide, and applies the attacker-supplied state directly: [3](#0-2) 

`Commit#create_status_from_github!` creates a `Status` record and, on a transition to `pending`/`success`, unconditionally schedules merge-queue processing for **that commit's own stack** — not the stack the webhook nominally came from: [4](#0-3) 

That scheduled job (`ProcessMergeRequestsJob`) merges any pending PR whose head passes `all_status_checks_passed?`: [5](#0-4) 

and `MergeRequest#all_status_checks_passed?` / `any_status_checks_missing?` rely solely on the `Status` rows attached to `head`, which is exactly what `StatusHandler` just wrote: [6](#0-5) 

**Binding broken (as an equality):** `organization/repository that authenticated the webhook signature` should equal `repository/stack whose commit row is mutated by that webhook`. In `StatusHandler` this equality is never enforced — the lookup key is the bare `sha`, so any commit anywhere in the installation whose SHA matches the attacker-chosen value receives the forged status, regardless of which repository actually produced it.

### Impact Explanation
This is a cross-repository write that can produce an **unauthorized merge or deploy**, one of the explicitly listed Critical impacts:
- If an attacker knows (or guesses/copies from public CI badges) the required status `context` name used by a target stack's `shipit.yml` (`ci.require` / `merge.require`, surfaced in `DeploySpec`), they can post a forged `success` status for the exact SHA of a pending, otherwise-unmergeable pull request's head commit in another repository/stack under the same GitHub organization.
- `ProcessMergeRequestsJob` will then merge that pull request via `MergeRequest#merge!`, which calls `stack.github_api.merge_pull_request(...)` using Shipit's own privileged GitHub credentials — an unauthorized merge performed with the app's authority, not the attacker's.
- The same forged status can also satisfy `Commit#deployable?` gating, enabling an unauthorized continuous-deployment run.

### Likelihood Explanation
Requires only: (1) the attacker to have push/collaborator access to any one repository belonging to a GitHub organization already onboarded to the Shipit instance (a low bar — organizations commonly onboard many repos, including test/sandbox ones), and (2) knowledge of a target stack's required-status context name and the target commit SHA (both are ordinarily discoverable — SHAs from public commit history/PRs, context names from `shipit.yml` or CI badges). No `ApiClient` token, webhook secret, or GitHub App private key is needed beyond what a legitimate low-privilege repo collaborator already has, since GitHub itself signs and delivers the webhook. This does not depend on the host application deviating from documented mounting.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository named in the webhook payload (mirroring the `stacks`/`Repository.from_github_repo_name(repository_name)` pattern used elsewhere), e.g. restrict to `Commit.joins(:stack).where(sha: params.sha, stack: { repository: repository_from_payload })`, so a status can only ever be applied to a commit that belongs to the stack whose repository actually emitted the event.

### Proof of Concept
1. Attacker is a collaborator on `org/low-trust-repo`, which is a stack onboarded to the same Shipit instance/organization as the target `org/high-trust-repo`.
2. Attacker learns that `org/high-trust-repo`'s `shipit.yml` requires status context `ci/circleci`, and identifies the head SHA `S` of an open, CI-pending pull request in `org/high-trust-repo`.
3. Using their write access to `org/low-trust-repo`, the attacker calls GitHub's Commit Status API against `org/low-trust-repo` with `sha=S`, `state=success`, `context=ci/circleci` (GitHub does not require the SHA to exist in that repo).
4. GitHub sends a `status` webhook to Shipit, signed with the organization's shared secret; `WebhooksController#verify_signature` accepts it because the org matches. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: 'S').each { |commit| commit.create_status_from_github!(params) }`, finding and updating the commit in `org/high-trust-repo`'s stack despite the event nominally being about `org/low-trust-repo`. [3](#0-2) 
6. The status transition schedules `ProcessMergeRequestsJob` for the target stack; `all_status_checks_passed?` now returns true, and the pull request is auto-merged using Shipit's own GitHub credentials — an unauthorized merge into `org/high-trust-repo`. [5](#0-4)

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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-30)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
