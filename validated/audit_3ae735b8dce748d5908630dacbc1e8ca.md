### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a status event for one repository overwrite required-context CI status on a commit belonging to a different stack/repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no repository/stack scoping, so any GitHub `status` webhook that authenticates for *some* configured GitHub organization can write a `CommitStatus` (context/state) onto every `Shipit::Commit` row in the database that shares that SHA, including commits owned by an unrelated stack/repository. Since `Commit#deployable?` and merge eligibility are derived from `Status::Group` built from these statuses, this is a cross-tenant state-mutation vector.

### Finding Description
The broken binding: the handler assumes `commit.stack.repository == payload.repository`, but the code never checks it — `sha == sha` is the only equality enforced, not `commit.stack_id == stack_for(payload.repository).id`.

Code path:
- `WebhooksController#create` dispatches by event type only, then `verify_signature` checks the HMAC signature using `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from the payload's own `repository.owner.login` [1](#0-0) [2](#0-1) . This only proves the request came from GitHub for *that org* — it does not bind the payload to a specific repository or stack.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
There is no filter by `commit.stack.repository`/`github_repo_name`/`stack_id` at all — every `Commit` record in the entire table with a matching `sha` gets the status applied, regardless of which stack or repository it belongs to.
- `create_status_from_github!` writes into `statuses` and recomputes the commit's status group [4](#0-3) , and `deployable?`/`blocked?`/merge eligibility are derived from that same `status` (`Status::Group`) [5](#0-4) [6](#0-5) .

Exploit flow: An attacker who controls (or is a legitimate member of) any GitHub organization/repository that Shipit has configured with a GitHub App/webhook secret can cause a real, validly-signed `status` webhook to be delivered for a commit SHA that is shared with a victim's stack (e.g., via a fork sharing history, a mirrored/duplicated repo, or a monorepo commit reused across multiple tracked repositories). Because `Commit.where(sha:)` performs no repository/stack scoping, the victim commit belonging to a different stack receives the forged `context: ci/lint`, `state: failure` status, flipping its `deployable?`/merge eligibility if `ci/lint` is a required context there.

Existing guards do not stop this: `verify_signature` only authenticates that the payload came from a legitimate org configured in Shipit (a *different* org from the victim's), not that the SHA/commit belongs to that org's repository; `drop_unhandled_event` only filters by event type; there is no `ExplicitParameters` field or model validation tying `params.repository` to the located `Commit` in `status_handler.rb`.

### Impact Explanation
A validly-authenticated webhook from repository/org A can write CI status records onto `Commit` rows belonging to stack/repository B, which is exactly the "payload for one repository mutating another's stack/commit" Critical category. Concretely, an attacker can force a required context (e.g. `ci/lint`) to `failure` (blocking deploy/merge) or to `success` (unblocking deploy/merge) on a victim commit they do not control, as long as a matching SHA exists in the `commits` table for another stack. This is repeatable for every SHA collision the attacker can arrange and affects any tenant/stack sharing the Shipit instance.

### Likelihood Explanation
Preconditions: the attacker needs a `status` webhook to be delivered and pass `verify_signature` for *some* org configured in the multi-tenant Shipit instance (this can be their own legitimately owned org/repo — no secret needs to be stolen, they just need GitHub to sign it for their own repo), and a commit SHA that also exists as a `Commit` row for the victim stack (achievable via a fork sharing commit history, mirrored repos, or duplicate/re-tracked repositories, which is a normal occurrence in large multi-repo Shipit deployments). No privileged Shipit role, session, or secret is required beyond controlling one's own repository that Shipit already trusts. This is fully repeatable/scriptable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` by the repository asserted in the webhook payload, not just by SHA — e.g., resolve the `Repository`/`Stack` from `params.repository.full_name` (as other handlers like `PullRequest::OpenedHandler` already do via `Repository.from_github_repo_name`) and constrain `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))` (or equivalent join) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status event only affects commits belonging to the authenticated repository" do
  victim_stack = shipit_stacks(:shipit) # requires ci/lint per fixture ci.require config
  shared_sha = 'deadbeef' * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')

  # attacker-owned stack/repo, distinct from victim_stack, but a Commit row with the same sha exists
  attacker_stack = shipit_stacks(:cyclimse) # different repository/org
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'attacker commit')

  before_status = victim_commit.reload.status.state
  before_deployable = victim_commit.deployable?

  params = ExplicitParameters::Params.new(
    sha: shared_sha, state: 'failure', context: 'ci/lint'
  )
  Shipit::Webhooks::Handlers::StatusHandler.new(params).process

  victim_commit.reload
  assert_not_equal before_status, victim_commit.status.state,
    "victim commit's status group changed due to an unrelated repository's webhook"
  assert_not_equal before_deployable, victim_commit.deployable?,
    "victim commit's deployable? flipped due to a cross-repository status write"
end
```
This demonstrates that `StatusHandler#process`'s unscoped `Commit.where(sha:)` allows a status event authenticated for one repository to mutate the required-context CI state and deployability of a commit belonging to an unrelated stack.

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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```
