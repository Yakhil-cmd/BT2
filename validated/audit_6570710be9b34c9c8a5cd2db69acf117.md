### Title
Cross-repository SHA collision in `StatusHandler#process` allows a webhook signed by an unrelated GitHub organization to inject a `success` status and trigger continuous deployment on an unrelated stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit purely by a global `Commit.where(sha: params.sha)` lookup, ignoring the `repository` field of the incoming payload that was actually used to authenticate the webhook. An attacker who owns any GitHub organization/repository registered in Shipit (org B) can send a `status` webhook — validly signed with B's own `webhook_secret` — that references a sha which happens to also exist as a commit on stack A (owned by a different, unrelated org). Shipit will attach the attacker-chosen `state` to that commit under stack A's `stack_id`, which can trigger continuous deployment of stack A.

### Finding Description
The binding the system is supposed to enforce is: `verified_org(repository_owner_in_payload) == org_owning_the_stack_whose_commit/status_is_mutated`. This holds at the controller level for most handlers because `Webhooks::Handlers::Handler#stacks` scopes lookups through `Repository.from_github_repo_name(repository_name)` [1](#0-0)  — i.e., the repository named in the (now-verified) payload is used to find the corresponding Shipit `Repository`/`Stack`.

`StatusHandler`, however, never uses this scoping. It queries commits globally by sha with no repository filter at all: [2](#0-1) 

`Commit#create_status_from_github!` then writes the status using the commit's own `stack_id` (the row's foreign key, belonging to whichever stack the sha was originally recorded against), not anything derived from the webhook payload: [3](#0-2) [4](#0-3) 

The controller's `verify_signature` step correctly authenticates that the payload was signed by whichever organization is named in `params.dig('repository','owner','login')` [5](#0-4) , but that only proves "this request genuinely came from org B" — it says nothing about which stack the sha inside the body should be applied to. `StatusHandler` conflates "a valid signature for *some* registered org" with "authorization to write a status for the stack that owns this sha", because it never checks that the sha it found actually belongs to a commit under the repository/org that signed the request.

**Exploit flow:**
1. Stack A has `continuous_deployment` enabled and an undeployed commit C that is not yet `deployable?` only because it lacks a `success` status.
2. Attacker owns/controls org B (a completely separate GitHub org with a Shipit-registered app/webhook secret, e.g. via their own onboarded repo).
3. Attacker creates a commit in repo B whose sha is byte-identical to commit C in A (achievable for content-addressable git objects by reproducing the same tree, parent chain, author/committer identity and timestamps and message — trivial for an empty/orphan commit, and readable off A's public commit if A is public).
4. Attacker POSTs a `status` event to `/webhooks` with `repository.full_name = "B/repo"`, `sha = C.sha`, `state = "success"`, signed with B's own valid `X-Hub-Signature` (computed with B's real `webhook_secret`, which the attacker legitimately possesses because it's their own org).
5. `verify_signature` succeeds (`repository_owner` = B, and the signature really was produced with B's secret) [6](#0-5) .
6. `StatusHandler#process` finds commit C purely by sha (ignoring that the payload says repo B) and calls `commit.create_status_from_github!(params)`, creating a `Status` with `stack_id = C.stack_id` (stack A) and `state: 'success'` [2](#0-1) .
7. `Status#schedule_continuous_delivery` fires on create [7](#0-6) , and `Commit#schedule_continuous_delivery` schedules `ContinuousDeliveryJob` once `deployable? && stack.continuous_deployment? && stack.deployable?` [8](#0-7) , which now becomes true because the missing `success` status was just supplied by the attacker.
8. This leads into `Stack#trigger_continuous_delivery`/`next_commit_to_deploy`/`trigger_deploy`, deploying stack A — a deploy triggered entirely by data controlled by an org with zero relationship to A.

None of the listed guards prevent this: `verify_signature` authenticates the sender org but is never cross-checked against the stack being mutated; `drop_unhandled_event`/`ExplicitParameters` only validate shape, not repository ownership; there is no `Repository`/`stacks` scoping call anywhere in `StatusHandler`.

### Impact Explanation
An attacker with no relationship to stack A can inject an arbitrary CI status (`success`, `failure`, `error`) onto any commit sha they can reproduce, using nothing but their own unrelated GitHub org's webhook credentials. When the target stack has `continuous_deployment` enabled, this can directly cause an **unauthorized deploy** of stack A — a payload from repository B mutating stack/commit state belonging to an entirely different tenant. This matches the explicitly listed Critical category: "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy". Blast radius spans every stack in the installation, since the sha lookup is completely global and unscoped by repository/organization.

### Likelihood Explanation
Preconditions: stack A must have `continuous_deployment` enabled and an otherwise-deployable commit blocked only by a missing/failing status (a common, realistic configuration). The attacker needs only an org/repo they legitimately control that is already onboarded to the same Shipit instance (or any org whose webhook secret Shipit can verify) — no session, API token, or access to stack A is required. The hard part is reproducing an identical sha, which is trivial for empty/orphan commits (identical tree, and attacker fully controls author/committer name, email, and timestamps to match a publicly-visible target commit) but harder for commits with substantive content requiring exact parent-chain history. For the specific scenario in the question (an empty commit), this is straightforward and repeatable against any stack whose commit shas are discoverable.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing sha-based lookups) to the repository/stacks named in the verified payload, mirroring the base `Handler#stacks` helper, e.g. restrict the `Commit.where(sha: ...)` query to `stacks.flat_map(&:commits)` or join through `Repository.from_github_repo_name(repository_name)` before updating statuses, so a status can only be applied to commits belonging to stacks under the repository that was actually authenticated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "a status payload for repository B cannot deploy stack A via a colliding sha" do
  stack_a = shipit_stacks(:shipit)
  stack_a.update!(continuous_deployment: true)
  commit = stack_a.commits.create!(sha: 'a' * 40, message: 'empty', author: shipit_users(:walrus), committer: shipit_users(:walrus))
  # commit currently not deployable? for lack of a success status

  # Payload claims to originate from an unrelated repository B, but references A's commit sha.
  payload = {
    'sha' => commit.sha,
    'state' => 'success',
    'context' => 'ci',
    'description' => 'forged',
    'target_url' => 'http://example.com',
    'created_at' => Time.now.iso8601,
    'repository' => { 'full_name' => 'attacker-org/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } },
  }

  assert_difference -> { stack_a.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  assert commit.reload.deployable?, "commit should not become deployable from a status signed by an unrelated org"
  # Binding under test: verified_org('attacker-org') != stack_a.repository.owner
  # yet stack_a.statuses now contains an attacker-supplied 'success' status.
end
```
This demonstrates that `StatusHandler` writes a `Status` bound to stack A's `stack_id` purely from a global sha match, with no verification that the authenticated organization (`attacker-org`) has any relationship to stack A — confirming the binding is broken and a full continuous-deployment trigger test (asserting `Deploy.count` increments for stack A after scheduling `ContinuousDeliveryJob`) would complete the Critical-impact proof.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-34)
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
