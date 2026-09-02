### Title
Cross-stack status forgery via sha-only commit lookup in `StatusHandler#process` bypasses `Commit#blocked?` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the commits to update purely by `sha`, with no check that the webhook's authenticated `repository` matches the commit's own `stack`. A correctly-signed `status` webhook for repository/stack B is applied to every `Commit` row in the database sharing that sha, including commits that actually belong to an unrelated stack A, letting a party who never authenticated as A write a `Status` into A and flip `Commit#blocked?` from `true` to `false`.

### Finding Description
The broken binding: the write target `status.stack_id` should equal the stack that the verified webhook is authenticated for (derived from `params['repository']`), i.e. `status.stack_id == stack_for(params['repository'])`. Instead the actual code computes `status.stack_id == commit.stack_id`, where `commit` is fetched with: [1](#0-0) 

`Commit.where(sha: params.sha)` is global — it is not scoped by `repository_owner`/`full_name` at all, so it matches any commit row in the whole installation with that sha, regardless of which stack/repo it belongs to. For each match, `commit.create_status_from_github!` is called, which writes the status against `commit.stack_id` (the commit's *own* stack, e.g. stack A) using the state/context taken straight from the forged payload: [2](#0-1) [3](#0-2) 

`Shipit::WebhooksController#verify_signature` only proves the payload was sent by GitHub for whatever organization the payload's `repository.owner.login` claims (`Shipit.github(organization: repository_owner)`); it never re-checks that the `repository` in the payload is the same repository the resolved `Commit` actually belongs to: [4](#0-3) 

So an attacker who legitimately controls a repository B that Shipit already tracks (e.g. their own repo inside an org whose GitHub App/webhook_secret is configured in Shipit, per the multi-org setup documented in `docs/setup.md`) can call the real GitHub Status API on their own repo B for a commit sha that is also present in stack A's `commits` table (a "shared-sha" commit — trivially true whenever the same underlying repository is tracked by more than one Shipit stack/environment, or when B and A share history). GitHub signs and delivers this event with B's real (Shipit-held) secret, so `verify_signature` passes. `StatusHandler#process` then finds the sha-matching `Commit` belonging to stack A and creates a `Status` on it with `stack_id = A`, `context` equal to one of A's `blocking_statuses`, and `state: 'success'`.

`Status::Common#blocking?` is `!success? && commit.blocking_statuses.include?(context)`: [5](#0-4) 

Because the forged status is `state: 'success'`, it is not itself "blocking", and it satisfies the required context for that commit's status group, so the previously-blocking commit stops being `blocking?`. `Commit#blocked?` on stack A then re-evaluates: [6](#0-5) 

and returns `false`, where before it returned `true`, making a previously-blocked candidate commit `deployable?` on stack A — a stack the attacker never authenticated against.

None of the listed guards catch this: `verify_signature` validates the *sender's* org, not the *target* commit's stack; the `ExplicitParameters` schema on `StatusHandler` only validates payload shape (`sha`, `state`, `context`, etc.), not repository ownership; there is no `force_github_authentication`, `require_permission!`, or model validation anywhere in this path that ties a `Status` to the repository claimed in the webhook payload.

### Impact Explanation
A `Status` record is written into stack A's commit/blocking-status graph by a party authenticated only for stack B, causing `Commit#blocked?` to flip from `true` to `false` on stack A. This can unblock a previously safety-gated deploy candidate and lead to `deployable?` becoming `true`, feeding continuous delivery (`schedule_continuous_delivery`) or manual deploy triggers for a repository the attacker never controlled or authenticated against. This is a cross-repository write ("a payload for one repository mutating another's stack/commit") and matches the Critical category (safety gate bypass, unauthorized deploy enablement). It is repeatable against any pair of stacks that ever share a commit sha (multiple stacks/environments tracking the same repo, or repos with shared history), and is not limited to a single victim stack — any stack sharing a sha with a repo the attacker can emit signed webhooks for is affected.

### Likelihood Explanation
Preconditions: (1) the attacker must be able to get a *validly signed* `status` webhook delivered to the shared `/webhooks` endpoint — this requires them to own/control a repository B that is already onboarded with a Shipit-recognized GitHub App/organization webhook_secret (a realistic, unprivileged condition for multi-repo/multi-stack or multi-org Shipit deployments, and trivial in single-org legacy config where `Shipit.github(organization: repository_owner)` ignores the organization argument entirely and always checks against the single configured secret); (2) a commit sha must exist identically in both B's and stack A's `commits` table, which naturally happens whenever the same repository is tracked by multiple stacks/environments (a common, documented Shipit pattern) or whenever forks/mirrors share history. Attacker cost is a single GitHub Status API call (`repo:status` scope) on their own repository; no Shipit secret, session, or API token is required. Fully repeatable per request.

### Recommendation
In `Shipit::Webhooks::Handlers::StatusHandler#process`, scope the `Commit` lookup by the webhook's authenticated repository, not by `sha` alone — e.g. resolve the target `Stack`(s) from `params['repository']['full_name']` (as `PushHandler`/other handlers do) and restrict `Commit.where(sha:, stack_id: matching_stack_ids)`. Reject or ignore matches whose commit's stack does not correspond to the repository that was cryptographically verified in `verify_signature`.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/status_handler_test.rb` (no live GitHub):

```ruby
test "a status webhook for repository B cannot unblock stack A via a shared sha" do
  stack_a = shipit_stacks(:shipit)
  stack_a.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => ['ci/required'] }))

  shared_sha = 'deadbeef' * 5
  commit_a = stack_a.commits.create!(sha: shared_sha, message: 'shared', authored_at: Time.now, committed_at: Time.now)
  # commit_a currently has no status for 'ci/required' => blocking? true, blocked? true for later commits
  assert_predicate commit_a, :blocking?

  # Forged payload as delivered/signed for an unrelated repository B, targeting the SAME sha
  params = ExplicitParameters::Parameters.new(
    sha: shared_sha,
    state: 'success',
    context: 'ci/required',
    created_at: Time.now.to_s
  )

  assert_difference -> { commit_a.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.new(params).process
  end

  commit_a.reload
  refute_predicate commit_a, :blocking? # binding broken: forged cross-repo status neutralized stack A's blocking check
end
```

Both sides of the binding before/after:
- Before: `stack_a.blocking_statuses == ['ci/required']` and `commit_a.blocking? == true` (no status satisfies the requirement) → `Commit#blocked?` on later commits `== true`.
- After forged webhook from B: `commit_a.blocking? == false` and any later commit's `Commit#blocked? == false`, even though B never signed a webhook for A and holds no `webhook_secret` for A's organization.

### Citations

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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
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

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
