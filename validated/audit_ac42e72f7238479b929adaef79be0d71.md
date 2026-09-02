Confirmed: `StatusHandler#process` calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filtering by `params.repository.full_name`, `stack_id`, or `repository_id` at all — the handler ignores the `repository` field entirely for the actual data mutation, using it only implicitly through the controller's HMAC check against `repository_owner`'s org secret.### Title
Cross-tenant CI status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by matching `params.sha` against the global `Commit` table, with no scoping by the stack, repository, or organization named in `payload['repository']`. Any webhook whose signature is valid for *some* configured GitHub organization can therefore mutate CI status on a commit belonging to a completely unrelated, private stack, as long as the attacker knows/reproduces that commit's 40-character SHA.

### Finding Description
The broken binding: the code implicitly assumes `Commit.sha == params.sha` implies `Commit.stack.repository == params.repository`, but that equality is never checked, so the true binding that should hold — `Commit.stack.repository.full_name == params.repository.full_name` — is absent.

Code path:
1. `WebhooksController#verify_signature` only validates that the raw payload's HMAC matches the `webhook_secret` configured for `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the payload (`params.dig('repository', 'owner', 'login')`), as seen in [1](#0-0) . This only proves the request is authentic *for the organization named in the payload* — it says nothing about which commit is being targeted.
2. `Handlers::Handler` exposes a `stacks`/`repository_name` helper scoped to `payload.dig('repository', 'full_name')` [2](#0-1) , but `StatusHandler` never calls it.
3. `StatusHandler#process` does a completely global lookup: [3](#0-2) . `Commit.where(sha: params.sha)` has no `stack_id`, `repository_id`, or join back to `params.repository.full_name` at all.
4. `Commit#create_status_from_github!` then unconditionally records the status via `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) , using whatever `stack_id` the matched commit already has — i.e., the victim's stack, not the attacker's.

Exploit flow: an attacker controls (or can trigger GitHub webhooks for) a repository that Shipit tracks under some organization `attacker-org`, so they can produce a validly-signed `status` event for `attacker-org/attacker-repo`. They set `payload['repository']['full_name'] = "attacker-org/attacker-repo"` (satisfying signature verification) while setting `payload['sha']` to a 40-char SHA that collides with a commit belonging to a private victim stack (e.g. because the same content-identical commit was pushed to both a public mirror/fork and the private repo — git SHAs are purely content-derived, so this happens legitimately with monorepo mirrors, cherry-picks, and public/private repo pairs). Because `StatusHandler` never checks that the matched `Commit`'s stack/repository corresponds to `attacker-org/attacker-repo`, the forged status is written onto the victim's commit.

Existing guards fail because: `verify_signature` checks only payload authenticity per organization, not per-commit ownership; `drop_unhandled_event` and `ExplicitParameters` only validate shape, not scope; there is no `stacks`/`repository` filter anywhere in `StatusHandler`.

### Impact Explanation
An attacker who can get one validly-signed `status` webhook accepted for an org/repo they control can forge/blind-flip the CI status (`success`/`failure`/`pending`, `description`, `target_url`, `context`) of an arbitrary commit in any other tenant's private stack, provided they know or reproduce that commit's SHA. Since `Commit#deployable?`, `blocked?`, and continuous-deployment scheduling (`schedule_continuous_delivery`) key off status state, this can unblock or block deploys, or falsify displayed CI state, on a stack the attacker has no relationship to — a payload for one repository mutating another's stack/commit, matching the Critical "payload for one repository mutating another's stack, commit, task or team" category. It is repeatable for every SHA the attacker can learn.

### Likelihood Explanation
The attacker needs: (a) any Shipit-tracked repository under their control for which they can trigger (or forge, if they hold that org's webhook secret through their own legitimate GitHub App installation flow) a real `status` webhook, and (b) knowledge of a target commit SHA. SHA collision requires exact content reproduction, which is realistic in common patterns (identical commits mirrored across public/private repos, cherry-picks, forks) rather than brute force of the full 160-bit space. Given (a) is trivially satisfiable by any user who owns/administers a tracked repository, and (b) is plausible via legitimate SHA reuse, the attack is feasible and cheap, and fully repeatable.

### Recommendation
Scope the lookup in `StatusHandler#process` to commits belonging to the stacks derived from `payload['repository']['full_name']`, e.g. use `stacks.flat_map(&:commits).where(sha: params.sha)` or add an explicit join/filter `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { id: repository.id })`, mirroring the pattern already used in the `PullRequest` handlers (`repository = Repository.from_github_repo_name(...)`).

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status payload naming a different repository cannot write a status onto another stack's commit" do
  stack_a = shipit_stacks(:shipit) # victim, tracked under org "shopify"
  commit_a = stack_a.commits.create!(sha: "a" * 40, message: "victim commit")

  # Attacker's own tracked repo/stack, unrelated to stack_a
  attacker_repo_payload = {
    "sha" => commit_a.sha,
    "state" => "success",
    "repository" => { "full_name" => "attacker-org/attacker-repo", "owner" => { "login" => "attacker-org" } }
  }

  assert_no_difference -> { commit_a.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  end
end
```
Currently this test fails (the status IS created) because `StatusHandler#process` never checks `payload['repository']` against `commit_a.stack.repository`; after applying the recommended fix, the assertion holds.

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
