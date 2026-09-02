### Title
Cross-repository CI status forgery via unscoped SHA lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The GitHub webhook `status` event is authenticated against the organization owning the reporting repository, but the handler that processes the event resolves the target `Commit` by SHA alone, with no check that the commit belongs to the repository/organization whose webhook signature was actually verified. This breaks the binding "organization/repository that authenticated the webhook" = "repository whose commit-status record is written."

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the signature using `repository_owner`, derived from the payload's own `repository.owner.login` (or `organization.login`) [1](#0-0) [2](#0-1) . This only proves the payload came from GitHub for *that* repository's organization — it says nothing about which `Commit` record in Shipit's database the event is allowed to affect.

Once verified, the payload is dispatched to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) . For `status` events, `StatusHandler#process` looks up commits **globally, by SHA only**, with no scoping to the reporting repository:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

`Commit.where(sha: ...)` is not scoped by `stack` or repository at all, unlike the base `Handler#stacks` helper which does scope by `payload.dig('repository', 'full_name')` [5](#0-4) . `StatusHandler` bypasses that helper entirely and queries `Commit` directly. `create_status_from_github!` then writes a `Status` row and can trigger merge scheduling: `stack.schedule_merges if new_status.pending? || new_status.success?` [6](#0-5) [7](#0-6) .

Because git commit SHAs are content-addressed, any actor with push access to *any* repository tracked by this Shipit instance can reproduce a commit object with an identical SHA to a commit that exists in a *different* tracked repository/stack (e.g., by cloning/cherry-picking the exact same commit content into their own repo), then use the GitHub Statuses API on their own repository to report an arbitrary state/context for that SHA. GitHub signs and delivers this webhook using the reporting repo's own organization secret — passing `verify_signature` legitimately — yet `StatusHandler` will apply the forged status to the matching `Commit` row(s) in **any** stack, including ones belonging to a different organization/repository that the attacker never authenticated against.

This is the direct analog of the reported bug class: a field inside a verified payload (`sha`) is used to select a target object (the `Commit`/`Stack`) whose identity was never itself covered or constrained by the verification step (which only bound the organization, not the specific commit/repository).

### Impact Explanation
A forged `success` status for a required CI context (`ci.require` / `merge.require` in `shipit.yml`, enforced via `Commit#deployable?` and `MergeRequest::StatusChecker`) [8](#0-7) [9](#0-8)  can make a commit in a victim stack appear deployable or mergeable when it never actually passed CI in that repository. Combined with `stack.schedule_merges` being triggered on the forged success [10](#0-9) , this can enable an unauthorized merge or deploy on a stack/repository the attacker does not control — satisfying the "unauthorized deploy, rollback or merge" / cross-repository write criteria.

### Likelihood Explanation
Exploitation requires: (1) the attacker controls or has push/API access to at least one repository already tracked as a Shipit stack (a low-privilege, self-service condition per the engine's repository-creation flow), and (2) the ability to reproduce an identical SHA to a commit in the target repository, which is straightforward given git's content-addressed commit hashing (cloning/replaying the exact same commit object into another repository yields an identical SHA). No access to `webhook_secret`, `api_clients_secret`, or any privileged Shipit account is required — only ordinary GitHub write access to one tracked repository. This is a realistic, low-effort path, though it depends on the victim commit's SHA being knowable/reproducible, which is true for any public commit.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and similarly audit `CheckSuiteHandler`, which already scopes via `stacks.where(branch: ...)` before matching SHA) to the repository identified in the verified webhook payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or explicitly filter by `stack_id in: stacks.pluck(:id)`, so that a commit status can only ever be applied to commits belonging to the repository/organization that produced and signed the webhook.

### Proof of Concept
1. Attacker has push access to `attacker-org/repo-a`, which is registered as a Shipit stack.
2. Attacker identifies a commit SHA `S` in `victim-org/repo-b` (also tracked by Shipit) that is required to pass a `ci.require` context to be deployable/mergeable.
3. Attacker clones/replicates the exact same commit content (same tree, parents, author/committer metadata/timestamps) into `attacker-org/repo-a`, producing an object with identical SHA `S`.
4. Attacker calls the GitHub Statuses API on `attacker-org/repo-b`... (on `repo-a`) for SHA `S` with `state: success`, `context: <required context>`.
5. GitHub sends a `status` webhook signed with `attacker-org`'s webhook secret; `WebhooksController#verify_signature` passes because it only checks `attacker-org`'s secret against `attacker-org`'s own payload [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: 'S')`, which matches the `Commit` row belonging to `victim-org/repo-b`'s stack, and applies the forged `success` status to it [4](#0-3) .
7. The victim stack's commit is now marked as passing required CI, potentially triggering an unauthorized deploy or merge via `stack.schedule_merges`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```

**File:** app/models/shipit/merge_request.rb (L37-39)
```ruby
      def required_statuses
        deploy_spec&.merge_request_required_statuses || []
      end
```
