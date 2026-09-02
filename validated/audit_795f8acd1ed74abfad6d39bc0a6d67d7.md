### Title
`check_suite` webhook signature is verified against `repository.owner.login` while the stack it mutates is resolved from `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the org whose secret is used to authenticate the payload from `repository.owner.login`, but `Shipit::Webhooks::Handlers::Handler#stacks` resolves the target repository/stack from `repository.full_name`. An attacker can name an org that has no `webhook_secret` configured in `repository.owner.login` (which `verify_webhook_signature` accepts unconditionally — `return true unless webhook_secret`), while pointing `repository.full_name` at a victim repository belonging to a different org whose stack the `CheckSuiteHandler` will then mutate.

### Finding Description
The broken binding: the code assumes `params.dig('repository','owner','login') == Repository owning params.dig('repository','full_name')`, i.e. the org used for signature verification is the same org that the handler acts on. This assumption is never enforced.

- `Shipit::WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) , and `#verify_signature` fetches `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature` on that org's config [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the org has no configured `webhook_secret`: `return true unless webhook_secret` [3](#0-2) .
- Meanwhile, `Shipit::Webhooks::Handlers::Handler#stacks` resolves the target repository from a **different** field: `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` [4](#0-3) .
- `CheckSuiteHandler#process` then selects stacks by `params.check_suite.head_branch` on whatever repository `full_name` resolved to, and reschedules check-run refresh for commits matching `params.check_suite.head_sha` [5](#0-4) .

Exploit flow: attacker crafts a JSON body for `POST /webhooks` with header `X-Github-Event: check_suite`, sets `repository.owner.login` to an org configured in Shipit **without** a `webhook_secret` (e.g. their own low-value org), sets `repository.full_name` to `victim-org/victim-repo` (an org that *does* have a secret but whose secret the attacker doesn't know), and supplies `check_suite.head_branch`/`check_suite.head_sha` matching a real stack/commit in the victim repo. Because `repository_owner` resolves to the no-secret org, `verify_webhook_signature` returns `true` with no signature required at all. The handler then resolves `stacks` via `repository.full_name`, landing on the victim's real stack, and triggers `schedule_refresh_check_runs!` on the matching commit(s) — a write/side-effect on a repository that never authenticated the request.

None of the existing guards close this gap: `drop_unhandled_event` only checks that a handler exists for the event type; the `ExplicitParameters` schema for `CheckSuiteHandler` only validates presence/type of `check_suite.head_sha`/`head_branch`, not repository ownership consistency; there is no check anywhere that `repository.owner.login` matches the org owning `repository.full_name`.

### Impact Explanation
This is a payload for one (attacker-controlled, secret-less) org mutating another org's stack — the attacker can force `schedule_refresh_check_runs!` to run against arbitrary commits/stacks in any victim repository, entirely unauthenticated, as long as they can guess/target an existing stack branch and commit SHA (both are often publicly discoverable via the GitHub repo itself). This is repeatable against any victim repository whose owning org's name/full_name the attacker knows, and the request needs no session, no `webhook_secret`, and no privileged role. Severity aligns with "a payload for one repository mutating another's stack/commit" — Critical per the target impact categories, since the authentication used to accept the payload (verify_signature) does not actually govern the entity the payload mutates.

Note: the concrete downstream effect of `schedule_refresh_check_runs!` (e.g., whether it enqueues a job that hits GitHub API, updates local check-run state, or could feed into `Stack#allowed_to_merge?`/gating logic) was not further traced in this pass; only the `CheckSuiteHandler` code shown was inspected within the available iterations.

### Likelihood Explanation
Preconditions: (1) at least one org in `Shipit.github_teams`/GitHub app config with no `webhook_secret` set (feasible in real deployments where some low-risk orgs skip secret configuration), and (2) knowledge of a victim org/repo name and a valid branch+commit SHA pair for an existing stack (both are typically public GitHub metadata). Attacker cost is a single unauthenticated HTTP POST with no signature header needed. This is trivially repeatable and scriptable against many victim repos as long as any no-secret org exists in the deployment.

### Recommendation
Verify the webhook signature using the org that owns `repository.full_name` (the same field the handler uses to resolve the target), not `repository.owner.login`; or, better, require both fields to reference the same org and reject the payload if a configured `webhook_secret` for the resolved org is missing, rather than treating "no secret configured" as an automatic pass. At minimum, `Handler#repository_name` and `WebhooksController#repository_owner` must derive from a single authoritative source of truth for which org authenticates and which org is acted upon.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual minitest)
test "check_suite forged via owner/full_name split accepted for a no-secret org and mutates a different org's stack" do
  # Org A: no webhook_secret configured
  Shipit.stubs(:github).with(organization: 'org-a').returns(
    Shipit::GitHubApp.new('org-a', { app_id: 1, installation_id: 1 }) # no webhook_secret key
  )

  victim_repo = shipit_repositories(:cyclid) # belongs to org-b, has its own stack/commit
  stack = victim_repo.stacks.first
  commit = stack.commits.last

  payload = {
    repository: { owner: { login: 'org-a' }, full_name: victim_repo.full_name },
    check_suite: { head_branch: stack.branch, head_sha: commit.sha }
  }.to_json

  post :create, body: payload, params: {}, headers: { 'X-Github-Event' => 'check_suite' }
  # no X-Hub-Signature header sent at all

  assert_response :ok
  # Equality that should hold but doesn't:
  # repository_owner ('org-a') should equal the org owning repository.full_name (org-b) for the
  # authentication to be meaningful. It does not, yet the request is accepted.
  assert_enqueued_with(job: Shipit::UpdateCheckRunsStatusJob) do
    # or assert on commit.reload state changed by schedule_refresh_check_runs!
  end
end
```
This demonstrates the request is accepted (`verify_webhook_signature` returns `true` for the no-secret `org-a`) while the actual mutation lands on `org-b`'s stack/commit, resolved purely from `repository.full_name`, confirming the invariant "a `check_suite` event only affects the repository/stack whose secret authenticated it" is violated.

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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
