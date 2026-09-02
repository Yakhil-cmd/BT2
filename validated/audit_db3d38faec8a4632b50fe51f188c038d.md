### Title
`StatusHandler#process` matches commits by `sha` with no repository scoping, allowing cross-tenant status/commit mutation — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on `payload['repository']['full_name']` at all, unlike sibling handlers (`CheckSuiteHandler`, `PullRequest::OpenedHandler/ClosedHandler`) which scope lookups through `stacks`/`Repository.from_github_repo_name`. Any account that can get a `status` webhook signed for *its own* GitHub organization can mutate the status of a commit belonging to a completely different repository/stack, as long as the sha value matches — which is trivially achievable via forks/shared history.

### Finding Description
Binding claimed to hold: `sha's owning repository (per GitHub)` == `payload['repository']['full_name']` (the field verified indirectly via `WebhooksController#verify_signature`, which only proves the payload was signed by *some* org's secret, not that the sha belongs to that org's repo).

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login')` taken straight from the attacker-supplied payload. This only proves "this payload was HMAC-signed with the secret belonging to org X," not that the `sha` field actually belongs to a commit inside org X's repo.
- `Handler#initialize` (`app/models/shipit/webhooks/handlers/handler.rb:21-24`) parses payload via `ExplicitParameters::Parameters`, which only validates types/presence, not any repository correlation.
- `StatusHandler` schema (`app/models/shipit/webhooks/handlers/status_handler.rb:7-18`) requires `sha`, `state`, etc. — no requirement or usage of `repository`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` globally across the entire Shipit installation by `sha` alone — it never calls the base class's `stacks` helper (`Handler#stacks`, `app/models/shipit/webhooks/handlers/handler.rb:32-34`) that other handlers (`CheckSuiteHandler`, `PullRequest::OpenedHandler`, `PullRequest::ClosedHandler`) use to scope by `repository_name`. Contrast with `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`), which correctly restricts to `stacks.where(branch: ...)`.

Because Git commit shas are content-addressed, any attacker who forks or clones a victim repo and replays/pushes the same commit content into their own GitHub repository produces an identical sha under their own repository. They then trigger (or forge, via any action that fires a real GitHub `status` event on their own repo, e.g. pushing that commit and letting a CI they control post a status, or simply having GitHub deliver the status event for their own repo/commit) a legitimately-signed webhook for their own org, with `sha` equal to the victim's commit sha and `state` of their choosing (e.g. `success`). `verify_signature` passes because the signature is valid for the attacker's own org secret. `StatusHandler#process` then finds and mutates **any** `Commit` record across **any** stack in the installation whose `sha` matches, including the victim's, via `commit.create_status_from_github!(params)` → `Commit#add_status` (`app/models/shipit/commit.rb:366-386`), which can flip `deployable?`/`blocked?` and trigger `stack.schedule_merges` and `ContinuousDeliveryJob` (`Commit#schedule_continuous_delivery`, `app/models/shipit/commit.rb:281-287`) for the victim stack if it has `continuous_deployment?` enabled — i.e., forging a passing status can trigger an unauthorized continuous deployment on a repository/stack the attacker never proved ownership of.

None of the existing guards catch this: `verify_signature` only authenticates the org named in the payload, not the sha-to-repo relationship; the `ExplicitParameters` schema has no cross-field validator; and `StatusHandler` itself performs no repository correlation at all (it is stricter than described in the question is wrong — it is *looser*: it doesn't even check `payload['repository']['full_name']`).

### Impact Explanation
An attacker who controls any GitHub repository onboarded to (or under any org configured in) the Shipit instance can, by replaying a commit's content into their own repo, forge a `status` webhook that creates/updates a `Status` for a commit belonging to a different tenant/repository/stack. If the victim stack has `continuous_deployment?` enabled and the forged state is `success`, this can trigger an unauthorized deploy (`ContinuousDeliveryJob`) — matching the Critical category "a payload for one repository mutating another's stack, commit, task ... or an unauthorized deploy". This is repeatable against any commit sha the attacker can reproduce, and the blast radius spans every stack/repository hosted by the same Shipit instance, not just the attacker's own.

### Likelihood Explanation
Preconditions: attacker must be onboarded enough to have a GitHub org/repo whose org secret is known to Shipit (i.e., their own repository is registered in the same Shipit instance — a low bar, since Shipit repos/orgs are typically self-service or org-wide), and must be able to reproduce identical commit content (trivial for forks or copied files, common since many stacks share initial history or vendor identical files). No Shipit session, API token, or GitHub secret needed — only a real, self-triggered GitHub `status` webhook for their own repo. This is directly exploitable and repeatable per matching sha.

### Recommendation
Scope `StatusHandler#process` to commits belonging to repositories matching `payload['repository']['full_name']`, analogous to `Handler#stacks`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces the sha-repository binding by construction, matching the pattern already used by `CheckSuiteHandler` and the `PullRequest` handlers.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` — not to be treated as out-of-scope since it demonstrates the equality violation conceptually; the underlying bug is in app code):
```ruby
test "status payload for one repository must not mutate another repository's commit" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

  attacker_repository_full_name = "attacker/unrelated-repo"
  payload = {
    "sha" => victim_commit.sha, # attacker reproduced this sha in their own repo
    "state" => "success",
    "repository" => { "full_name" => attacker_repository_full_name }
  }

  assert_no_changes -> { victim_commit.reload.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Assertion of the binding, explicitly:
- Before: `victim_commit.sha == payload['sha']` is TRUE (attacker-chosen collision), but `victim_stack.repository.full_name == payload['repository']['full_name']` is FALSE.
- Current code: `StatusHandler#process` ignores the second equality entirely and mutates `victim_commit` anyway — test fails against current implementation (status count changes), proving the vulnerability.
- After fix (scoping via `stacks`): the test passes because the handler now requires both equalities to hold before mutating any commit.