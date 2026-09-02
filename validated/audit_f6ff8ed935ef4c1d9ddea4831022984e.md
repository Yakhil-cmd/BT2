### Title
StatusHandler mutates commit status across arbitrary repositories/stacks via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `params.sha` with no repository/stack scoping, unlike its sibling `CheckSuiteHandler`, which scopes lookups through `stacks.where(branch: ...)` before matching a sha. `params.branches` is accepted by the schema but never read in `process`, and the webhook's `repository` field is used only for HMAC signature selection, not for restricting which `Commit` rows may be mutated.

### Finding Description
The broken binding: the intended invariant is `status.commit.stack.repository == payload.repository`, i.e., a `status` webhook for repository R should only be able to create a `Status` for a `Commit` that belongs to a `Stack` of repository R. The actual code enforces only `Commit.sha == params.sha`, with no join/scope on stack or repository: [1](#0-0) 

Compare with `CheckSuiteHandler`, which correctly scopes through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) before matching sha: [2](#0-1) 

The base `Handler` class exposes a `stacks` helper precisely for this purpose, scoped by the payload's `repository.full_name`, but `StatusHandler` never calls it: [3](#0-2) 

The `branches` param is declared in the schema but unused in `process`: [4](#0-3) 

Signature verification (`verify_signature`) only confirms the payload was signed with the secret belonging to `repository_owner` (the org named in the payload itself); it says nothing about which `sha` values that payload may reference: [5](#0-4) 

**Exploit flow:** An attacker who owns/administers a repository (and thus can legitimately configure a real GitHub webhook + know the correct secret for their own org, or send a validly-signed payload for an org they control) crafts a `status` event payload where `repository.owner.login` matches an org they control (so `verify_signature` passes), but sets `sha` to a 40-character SHA that they know or guess belongs to a commit in an entirely different, victim stack/repository (`branches: []`, since branches are never read). Because `StatusHandler#process` performs a bare `Commit.where(sha: params.sha)` with no repository check, this creates a `Status` row on the victim's `Commit`, triggering `Commit#create_status_from_github!` / `add_status`, which can fire `deployable_status` hooks and call `stack.schedule_merges` — mutating the victim's pipeline state (e.g., forging a `success` status that unblocks an auto-merge/auto-deploy) despite the attacker having no relationship to that stack or repository.

Existing guards do not close this gap: `verify_signature` authenticates the org named in the payload, not the target of the sha lookup; `ExplicitParameters` only validates types/shape of `branches`, it does not enforce that they correspond to a real stack; there is no `stacks`/`Repository.from_github_repo_name` scoping call anywhere in `StatusHandler`.

### Impact Explanation
An attacker who controls any repository onboarded to the Shipit instance (or otherwise obtains a validly-signed `status` payload for one org) can create arbitrary `Status` rows for commits belonging to a completely different repository/stack, as long as they know or can guess the target commit's SHA (commit SHAs are frequently public information on GitHub, e.g., from public repos, PRs, or leaked via other Shipit endpoints). This is a cross-tenant mutation: "a payload for one repository mutating another's stack, commit, task or team," matching the **Critical** severity category. Depending on hook configuration (`Hook.emit(:deployable_status, ...)`) and `stack.schedule_merges`, this can influence merge/deploy automation for a victim stack the attacker has no legitimate access to. The attack is repeatable against any commit SHA the attacker can enumerate, across arbitrary target repositories.

### Likelihood Explanation
Preconditions: the attacker needs the ability to send a webhook payload that passes `verify_signature` for some organization (i.e., they legitimately administer at least one repo/org onboarded into Shipit, which is a low-privilege, self-service action per this engine's threat model — "any GitHub user who can push to a fork/repo they own"), and they need to know a target commit SHA (often discoverable from public GitHub activity). No Shipit session, API token, or GitHub App secret for the victim org is required. This is inexpensive and fully repeatable.

### Recommendation
Scope `StatusHandler#process` to only match commits belonging to stacks of the repository named in the payload, mirroring `CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This uses the existing `stacks` helper (scoped via `Repository.from_github_repo_name(repository_name)`) so a status webhook can only mutate commits that actually belong to the reporting repository.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` (or `test/models/shipit/webhooks/handlers_test.rb`), add:
1. Create a victim `Stack`/`Repository` (e.g., `foo/bar`) and a `Commit` with sha `"deadbeef..."` belonging to it.
2. Create/stub a second, unrelated `Repository` `attacker/repo` (or reuse `repository_params` pointing at a different `full_name`).
3. Stub `verify_signature` to succeed (as existing tests do) and post a `status` payload with `repository.full_name = "attacker/repo"`, `sha` equal to the victim commit's sha, and `branches: []`.
4. Assert:
```ruby
assert_difference 'victim_commit.statuses.count', 1 do
  post :create, body: payload, as: :json
end
```
This demonstrates that a status payload declaring an unrelated `attacker/repo` still creates a `Status` on the victim commit purely because the sha matches — confirming the binding `status.commit.stack.repository == payload.repository` is not enforced.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
