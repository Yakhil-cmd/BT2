## Title
Cross-tenant status forgery via unscoped commit lookup in `StatusHandler#process` triggers unauthorized deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

## Summary
`StatusHandler#process` looks up commits by SHA alone, across the entire `commits` table, with no scoping to the repository/organization that the webhook signature actually authenticated. Every other handler in this codebase (`PushHandler`, the `PullRequest::*` handlers) uses the base class's `stacks` helper, which resolves `Repository.from_github_repo_name(repository_name)` before touching any `Stack`/`Commit` records, but `StatusHandler` skips that helper entirely.

## Finding Description
The binding that should hold is: `organization_that_signed(payload) == organization_owning(stack_of(commit_written))`. Tracing the code shows this is not enforced for the `status` event.

- `WebhooksController#verify_signature` resolves the GitHub App/webhook secret using `repository_owner`, itself read straight from `params.dig('repository','owner','login')` in the attacker's own payload [1](#0-0) [2](#0-1) . This only proves the request was signed by *some* organization's configured webhook secret — the attacker's own org, in a multi-org Shipit deployment (as shown by `test/dummy/config/secrets_double_github_app.yml`) — not that it is authorized to write status for a specific `Stack`.
- `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This queries `Commit` globally by `sha`, with no `Repository`/`Stack` scoping whatsoever, and applies the attacker-supplied `state`/`description`/`target_url` to whatever `Commit` record(s) match — regardless of which organization or repository that commit's `Stack` belongs to.
- Contrast this with the base `Handler#stacks` helper, which every other handler uses to scope to the repository named in the payload: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none` [4](#0-3) , and `PushHandler#process`, which calls `stacks.not_archived.where(branch:)` before acting [5](#0-4) . `StatusHandler` never calls `stacks` at all.
- Once a matching `Commit` row is found (by sha only), `Status.create` fires `after_commit :schedule_continuous_delivery`, which calls `commit.schedule_continuous_delivery` [6](#0-5) [7](#0-6) , ultimately reaching `Stack#next_commit_to_deploy`/`Stack#deployable_commits` and `Stack#trigger_deploy`, which runs the deploy `Task` (and its `Command#start`/`PTY.spawn` with `GITHUB_TOKEN` in the environment) for the victim stack — a stack belonging to an organization the attacker never authenticated against.
- Exploit precondition: two `Stack`s (attacker's own, and the victim's) must have commits sharing the same `sha`. Because git SHAs are content-derived, this is realistic when the attacker's Shipit-tracked repo shares history with the victim's (e.g., a public fork, a shared upstream/mirror, or any scenario where the victim's public commit sha is known and also present in a repo the attacker controls and has connected to their own Shipit stack). The attacker does not need the victim's webhook secret, GitHub App key, or any Shipit credential — only a validly signed payload for their own org and the target sha (trivially obtainable for public repos via the GitHub commit API/UI).
- None of the existing guards catch this: `verify_signature` only checks the signature against the org named in the payload, not against the actual `Stack`/`Commit` being mutated; `ExplicitParameters` (`params do requires :sha ... end`) only validates types, not ownership; there is no `drop_unhandled_event` or `force_github_authentication` relevance here since this is server-to-server webhook traffic, not a user session.

## Impact Explanation
A payload signed only by the attacker's own organization's webhook secret can create a `Status` record on, and trigger continuous delivery for, a `Stack` belonging to an entirely different, victim organization. This matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" (Critical): it results in an unauthorized `Task`/deploy execution (`Command#start`/`PTY.spawn`, with `GITHUB_TOKEN` in the environment) against victim code/infrastructure, initiated purely by an attacker-controlled webhook delivery with no action from any victim-authorized user. The attack is repeatable against any stack whose current blocking commit sha can be learned and which shares that sha with a repository the attacker controls in the same Shipit instance.

## Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment hosting more than one organization's stacks (documented/supported configuration, per `secrets_double_github_app.yml`), (2) the victim stack in `continuous_deployment` mode, unlocked, unarchived, blocked only on a green CI status for its oldest undeployed commit, and (3) the attacker being able to produce/know a commit with the exact same sha in a repo they control (realistic for forks/shared history of public repos) or otherwise directly learn the sha and get it recorded under a `Commit` row they can trigger a status for. Attacker cost is one signed HTTP POST to `/webhooks`; no privileged role, session, or secret is needed beyond their own org's ability to sign their own webhook traffic.

## Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring the other handlers: use `stacks` (i.e., `Repository.from_github_repo_name(repository_name)&.stacks`) to constrain which `Stack`s/`Commit`s can be updated, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status can only be applied to commits belonging to the repository that actually signed the payload.

## Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two `Repository`/`Stack` fixtures for different "organizations" — `victim_repo` (`full_name: "victim-org/app"`) with a `Stack` in `continuous_deployment: true`, unlocked, unarchived, and a `Commit` `victim_commit` with `sha: "deadbeef..."` that is the oldest undeployed commit and currently blocked only on CI.
2. Create an unrelated `attacker_repo` (`full_name: "attacker-org/app"`) whose payload's `repository.full_name` is `"attacker-org/app"` but whose `sha` param equals `victim_commit.sha`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call({ "sha" => victim_commit.sha, "state" => "success", "repository" => { "full_name" => "attacker-org/app", "owner" => { "login" => "attacker-org" } } })` directly (bypassing only the controller's signature check, which is legitimately satisfied by the attacker for their own org).
4. Assert: `victim_commit.reload.state == "success"` (status was written for the victim's commit despite the payload naming `attacker-org/app`), and `assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_id: victim_stack.id])` or expect `Stack#trigger_deploy`/`Task#enqueue` to be called for `victim_stack` — proving a cross-org write and deploy trigger occurred from a payload that never authenticated against `victim-org`.
5. Contrast assertion: repeat the same test using `PushHandler` with a mismatched `repository.full_name` and show no cross-stack effect occurs (demonstrating the other handlers correctly scope via `stacks`, while `StatusHandler` does not).

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/status.rb (L19-19)
```ruby
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
