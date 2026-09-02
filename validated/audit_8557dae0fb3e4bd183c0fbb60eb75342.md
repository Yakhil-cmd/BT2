### Title
Cross-repository forgery of commit CI status via `StatusHandler` breaks the authenticated-organization ↔ written-repository binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController` authenticates an incoming webhook against the GitHub App belonging to the organization named in the payload's `repository.owner.login` field, but `StatusHandler` — the handler invoked for `status` events — never re-checks that field when deciding which `Commit` to mutate. It looks up commits globally by `sha` across the entire Shipit installation, so an organization that legitimately owns and signs webhooks for *its own* repository can inject a CI status onto a commit belonging to a completely different organization's stack.

### Finding Description
Signature verification is scoped by `repository_owner`, computed from the payload itself: [1](#0-0) [2](#0-1) 

This uses `Shipit.github(organization: repository_owner)` — i.e., the GitHub App/secret registered for the organization named in `repository.owner.login` (or `organization.login`) inside the payload. Verification only proves the request was signed by *that organization's* configured webhook secret; it says nothing about any other field in the payload.

The generic `Handler` base class does provide a `stacks` helper that scopes lookups to the repository named in the payload: [3](#0-2) 

`PushHandler` correctly filters through `stacks` (bound to `repository.full_name`) before acting: [4](#0-3) 

However, `StatusHandler` bypasses this scoping entirely and matches commits by `sha` across the whole installation, with no repository/organization filter at all: [5](#0-4) 

`Commit.where(sha: params.sha)` is a global, cross-tenant query. Since git SHAs are 40-character hex digests derived from commit content and are frequently public (mirrored/public repos, PR branches, etc.), an attacker who legitimately controls one organization's GitHub App/webhook secret can craft a `status` event whose `repository` field names their own org (so it passes `verify_signature`), but whose `sha` field is the SHA of a commit that belongs to an entirely different organization's `Stack` inside the same Shipit instance. `StatusHandler` will happily create a `Status` record on that foreign commit via `create_status_from_github!`: [6](#0-5) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository.owner.login in payload)` == `organization/stack that owns the Commit actually written by StatusHandler`

Before the report's referenced fix pattern (scoping by repository), these are never compared for `status` events — only for `push`.

### Impact Explanation
A forged `Status` record on a foreign commit is not merely cosmetic: `add_status` reacts to state transitions and can trigger real automation: [7](#0-6) 

Specifically:
- `stack.schedule_merges` is invoked when the new status is `pending` or `success`, feeding `ProcessMergeRequestsJob`.
- `MergeRequest#all_status_checks_passed?` / `#any_status_checks_failed?` evaluate `head.statuses_and_check_runs`, which include the forged `Status`: [8](#0-7) 

- `ProcessMergeRequestsJob#perform` merges a pending PR once `all_status_checks_passed?` is true: [9](#0-8) 

If the target commit is the head of a pending merge request in a victim organization's merge queue and is only blocked by a missing/pending CI status context, an attacker-controlled organization can post a fabricated `success` status for that exact `sha`+`context` and cause `MergeRequest#merge!` to fire, calling `stack.github_api.merge_pull_request` — an **unauthorized merge** on a repository the attacker's authenticated organization never had rights over. `Commit#deployable?` is likewise influenced by status state and can affect continuous-deployment scheduling: [10](#0-9) 

This satisfies the "unauthorized deploy, rollback, or merge" Critical-impact criterion, achieved purely by crossing the organization-authenticated vs. repository-written boundary — no `ApiClient` token, webhook secret of the victim, or repository write access is required, only the attacker's own (valid, unprivileged relative to the victim) GitHub App installation.

### Likelihood Explanation
The attacker needs: (1) their own legitimately configured GitHub organization/App on the same Shipit instance (a standard, low-privilege setup covered by `Shipit.github(organization: ...)`'s per-org config), and (2) knowledge of a target commit SHA in a victim stack that is pending on a specific status context. SHAs of the exact commit under merge-queue review are frequently discoverable (public repos, PR pages, Shipit's own UI/API for commits/deploys which is often open to a broader audience than deploy permissions). No cryptographic secret of the victim organization needs to be known. This is a straightforward, repeatable, low-cost attack once multi-organization/App configuration is in place, which the docs explicitly support (`docs/setup.md` "Using Multiple Github Applications").

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository/organization that authenticated the request, mirroring `PushHandler`'s use of `stacks`/`repository_name`:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently join `Commit` through `stack: :repository` filtered by `payload.dig('repository', 'full_name')`, so a status can only ever be attached to a commit belonging to the same repository that signed the webhook.

### Proof of Concept
1. Attacker controls Org A, with a valid GitHub App installed and configured in Shipit's `config/secrets.yml` (`github.OrgA.webhook_secret`).
2. Victim Org B has a stack with a pending `MergeRequest` whose head commit `sha = X` is blocked only by a missing/pending status with context `ci/required`.
3. Attacker sends a `status` webhook event to `/webhooks`:
   - Headers: `X-Github-Event: status`, `X-Hub-Signature` computed with Org A's `webhook_secret`.
   - Body: `{"sha": "X", "state": "success", "context": "ci/required", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/some-repo"}}`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "OrgA"`, uses Org A's webhook secret, verification succeeds.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: "X")` — finds the victim's commit belonging to Org B's stack — and calls `create_status_from_github!`, creating a `success` status for `ci/required` on that commit.
6. `add_status` triggers `stack.schedule_merges`; `ProcessMergeRequestsJob` re-evaluates the pending merge request, finds `all_status_checks_passed?` now true, and calls `merge_request.merge!`, invoking `stack.github_api.merge_pull_request` on Org B's repository — a merge performed by an entity (Org A) that was never authorized on Org B's repository.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

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

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
```
