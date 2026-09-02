### Title
Webhook signature verification keys off `repository.owner.login` while `PushHandler`/`CheckSuiteHandler` mutate the stack named by `repository.full_name`, allowing cross-organization stack mutation - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to check against using `repository_owner` (`payload.dig('repository','owner','login')`), while `Handler#stacks`/`#repository_name` (used by `PushHandler` and `CheckSuiteHandler`) resolve the target `Repository`/`Stack` using `payload.dig('repository','full_name')`. These two fields are read independently from the same attacker-controlled JSON body and are never cross-checked, so a request that authenticates as one organization can mutate a stack belonging to a different organization.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`organization_verified (repository.owner.login used in Shipit.github(organization:))` == `organization_named_by (owner segment of repository.full_name used by Handler#stacks)`.

Code path:
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes `repository_owner` via `payload.dig('repository','owner','login') || payload.dig('organization','login')` (line 61) and looks up `Shipit.github(organization: repository_owner)` to fetch that org's `webhook_secret`. [1](#0-0) [2](#0-1) 
- In `lib/shipit/github_app.rb`, `verify_webhook_signature` returns `true` unconditionally when the resolved org has no `webhook_secret` configured: `return true unless webhook_secret` (line 77). [3](#0-2) 
- Independently, `Handler#stacks`/`#repository_name` in `app/models/shipit/webhooks/handlers/handler.rb:32-38` resolves the mutated `Repository`/`Stack` set using `payload.dig('repository','full_name')`, without ever reading or comparing `repository.owner.login`. [4](#0-3) 
- `PushHandler#process` and `CheckSuiteHandler#process` both call the inherited `stacks` and act on whatever `Repository`/`Stack` it resolves (triggering `GithubSyncJob`/`sync_github` and `schedule_refresh_check_runs!`). [5](#0-4) [6](#0-5) 

Exploit flow: attacker registers/administers `attacker-org` in Shipit's GitHub app config with no `webhook_secret` set (per rules, this is granted as attacker-controlled configuration). Attacker sends a raw HTTP POST directly to `/webhooks` (no live GitHub, no signature required since `attacker-org` has no secret) with `X-Github-Event: push` and a body such as:
```json
{ "ref": "refs/heads/master", "after": "<sha>",
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" } }
```
`verify_signature` resolves `repository_owner = "attacker-org"`, finds no `webhook_secret`, and passes unconditionally. `PushHandler` then resolves `stacks` via `repository_name = "victim-org/victim-repo"`, finds `victim-org/victim-repo`'s stacks, and enqueues `GithubSyncJob` for a branch matching `params.ref` — a real, cross-tenant mutation on a repository the attacker never authenticated against. The same divergence applies to `CheckSuiteHandler`, which calls `schedule_refresh_check_runs!` on victim commits.

This does **not** hold for every handler as the question asserts, however:
- `StatusHandler#process` never calls `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` globally, unscoped by repository entirely (a related but distinct issue, not the owner/full_name divergence described). [7](#0-6) 
- `MembershipHandler#process` does not use `repository_name`/`full_name` either; its authorization-relevant value, `params.organization.login`, is exactly the same field (`organization.login`) used as the fallback in `repository_owner` for signature verification, so verified-org and mutated-org are identical for this handler — no divergence exists here. [8](#0-7) [2](#0-1) 

Existing guards that fail to prevent this: `drop_unhandled_event` only filters by event type, not payload content; `ExplicitParameters` schemas for `PushHandler`/`CheckSuiteHandler` never require or validate `repository.owner`, so nothing forces the two fields to agree; and `verify_signature` catches `GithubOrganizationUnknown` only when the org name is unrecognized, not when it's recognized but weakly configured.

### Impact Explanation
An unprivileged attacker who can get one organization registered in Shipit's config without a `webhook_secret` (or otherwise control an org with no secret) can force writes/mutations against **any other** organization's stacks: triggering `GithubSyncJob` (`PushHandler`) or `schedule_refresh_check_runs!` (`CheckSuiteHandler`) for arbitrary victim repositories/stacks, entirely bypassing that victim organization's webhook authentication. This is a genuine "payload for one repository mutating another's stack/commit" scenario (Critical category), repeatable against arbitrary stacks with no live GitHub interaction, and scoped across tenants sharing one Shipit deployment.

### Likelihood Explanation
Requires: (1) at least one Shipit-configured GitHub organization lacking `webhook_secret`, which the attacker can name in the `repository.owner.login` field of a forged payload (whether they administer that org or merely know its name is irrelevant to `verify_webhook_signature`'s unconditional pass), and (2) direct HTTP access to the `/webhooks` endpoint, which is publicly reachable by design. No GitHub secrets, session, or API token are needed. This is low-cost and fully repeatable for `push` and `check_suite` events against `PushHandler`/`CheckSuiteHandler`.

### Recommendation
Cross-validate that the org used for signature verification matches the org embedded in `repository.full_name` (and any `organization.login` field) before dispatching to handlers — reject or short-circuit if they diverge. Additionally, require and enforce `webhook_secret` presence for all configured organizations (make it non-optional), and have `StatusHandler` scope `Commit` lookups by the verified repository rather than querying all commits by `sha`.

### Proof of Concept
Parameterized minitest under `test/models/shipit/webhooks/handlers_test.rb` (or `test/controllers/webhooks_controller_test.rb`):
```ruby
test "push/check_suite handlers mutate victim stack when owner used for verification diverges from full_name" do
  victim_stack = shipit_stacks(:shipit) # owner "shopify", branch "master"
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    stub(verify_webhook_signature: true) # simulates no webhook_secret configured
  )

  payload = {
    "ref" => "refs/heads/master",
    "after" => "abc123",
    "repository" => { "owner" => { "login" => "attacker-org" }, "full_name" => victim_stack.repository.full_name }
  }

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "abc123"]) do
    request.headers['X-Github-Event'] = 'push'
    post :create, body: payload.to_json, as: :json
  end
end
```
Assert on both sides of the binding: `repository_owner` computed by the controller (`"attacker-org"`, unverified/secret-less) vs. `Handler#repository_name` (`victim_stack.repository.full_name`) — show they differ yet the mutation (`GithubSyncJob` enqueue / `schedule_refresh_check_runs!`) still executes against the victim stack.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
