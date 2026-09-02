### Title
Cross-repository `sha` collision in `StatusHandler#process` lets an attacker's own CI `success` status flip a victim commit's `deployable?` and trigger an unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is not scoped to the repository that the webhook signature was verified for. Any `Commit` row across the whole Shipit installation sharing that `sha` gets `create_status_from_github!` applied, so a `status` webhook legitimately signed for the attacker's own repository/organization can flip a victim stack's commit to `deployable?` and, with `continuous_deployment: true`, trigger `Stack#trigger_continuous_delivery` / `ContinuousDeliveryJob` against the victim's stack.

### Finding Description
The broken binding: `payload.repository.owner.login` (used by `WebhooksController#verify_signature` to select the `github_app`/secret to check the signature against) must equal `commit.stack.repository.owner` for every `Commit` mutated by the handler. In `StatusHandler#process`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

there is no `stack_id`/repository filter — the query matches every `Commit` row in the database with that `sha`, regardless of which stack/repository it belongs to.

`WebhooksController#verify_signature` only proves that the payload was signed with the webhook secret associated with `repository_owner` taken from the payload itself (`params.dig('repository','owner','login')`), i.e., it authenticates "this payload came from a webhook configured for org X," not "every commit sha in this payload belongs to org X's repositories": [2](#0-1) [3](#0-2) 

Since Git commit SHAs are content-addressed, an attacker who forks/mirrors a victim's public repository (or otherwise reproduces an identical commit — e.g., by pushing the same tree/parents/author/committer/message) will have a `Commit` row for the same `sha` in their own attacker-controlled Shipit stack. The attacker's own CI can then emit a `status` webhook with `state: "success"` for that `sha`, signed by their own repository's configured webhook secret, which passes `verify_signature` for the attacker's own organization. `StatusHandler#process` then applies this attacker-authored status to **every** `Commit` row with that `sha`, including the victim's, via `create_status_from_github!` → `statuses.replicate_from_github!` [4](#0-3) .

Once the victim's `Commit#status` reflects `success`, `Commit#deployable?`:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [5](#0-4) 
can flip to `true`, and `add_status` (called from `create_status_from_github!`) triggers `stack.schedule_merges` and, via `after_commit :schedule_continuous_delivery`, `Commit#schedule_continuous_delivery` checks `deployable? && stack.continuous_deployment? && stack.deployable?` and enqueues `ContinuousDeliveryJob.perform_later(stack)` [6](#0-5) , ultimately leading to `Stack#trigger_continuous_delivery` deploying the victim's commit.

None of the existing guards prevent this: `verify_signature` authenticates the sender's organization/secret but never cross-checks the `sha`'s owning stack; `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of `state`/`sha`/etc., not repository ownership; there is no `stacks` scope or per-repository filter applied in `StatusHandler#process`.

### Impact Explanation
An attacker with no privileges on the victim's Shipit stack can cause a write (a fabricated success `Status` record) to be persisted against the victim's `Commit`, and if the victim stack has `continuous_deployment: true`, an unauthorized `Deploy`/`ContinuousDeliveryJob` is enqueued and executed on the victim's deploy host using the victim's deploy configuration/credentials. This is a cross-tenant record mutation and unauthorized deploy — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." It is repeatable against any repository where an identical commit sha can be produced (trivially true for forks of public repos, and possible for any repo if the attacker can reproduce an identical commit object).

### Likelihood Explanation
Preconditions: (1) the victim stack must have a `Commit` row with a `sha` the attacker can also produce in their own repository (straightforward for any forkable/public repo, or any commit whose content the attacker can replicate byte-for-byte, since SHA1 is content-derived not repo-derived); (2) the victim stack should have `continuous_deployment: true` for the deploy-trigger part of the impact (the cross-tenant status-write alone is already a valid mutation regardless). Attacker cost is low: fork the repo, push/build to trigger their own CI, or send a raw `POST /webhooks` request with a `status` event payload signed using their own configured GitHub App/webhook secret for their own org. No Shipit credentials, session, or API token are required. This is fully repeatable and scriptable.

### Recommendation
Scope `Commit.where(sha: params.sha)` in `StatusHandler#process` to only commits belonging to stacks whose repository matches the authenticated `repository_owner`/`repository.full_name` from the verified webhook payload (e.g., join through `stack.repository` and filter by `owner`/`name`), mirroring the repository binding already established by `verify_signature`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook for one repo's sha cannot deploy another repo's stack" do
  victim_stack = shipit_stacks(:shipit) # continuous_deployment: true
  shared_sha = "deadbeef" * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit", ...)
  attacker_stack = create_stack!(repository: "attacker/attacker-repo")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "victim commit", ...)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'owner' => { 'login' => 'attacker' }, 'full_name' => 'attacker/attacker-repo' }
  }

  # signature computed with attacker org's webhook secret -> passes verify_signature
  assert_no_difference -> { victim_commit.reload.deployable? ? 1 : 0 } do
    # or explicitly:
  end

  assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [victim_stack]) do
    post shipit.webhooks_path, params: payload.to_json,
         headers: { 'X-Github-Event' => 'status', 'X-Hub-Signature' => attacker_signature }
  end

  assert victim_commit.reload.deployable?, "victim commit should not be flipped to deployable by attacker's own-org webhook"
end
```
Expected (current, vulnerable) behavior: the victim commit's status is updated and `ContinuousDeliveryJob`/`Deploy` gets enqueued for `victim_stack` even though the signed payload's `repository.owner.login` is `attacker`, not the victim's organization — demonstrating the binding break.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
