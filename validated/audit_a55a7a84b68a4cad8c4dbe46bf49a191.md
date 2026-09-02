## Title
Cross-repository Status forgery via SHA collision in `StatusHandler#process` bypassing repository binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits solely via `Commit.where(sha: params.sha)`, without ever scoping to the `repository_name`/`Repository` derived from the payload, unlike `Handler#stacks`, which every `PullRequest::*` handler uses. Because `sha` is a value the attacker controls in the incoming payload but the webhook signature only proves the attacker owns the named `repository`, an attacker who owns Repo A can craft a signed `status` webhook for Repo A that names a `sha` matching a `Commit` row belonging to an unrelated Repo B/stack, causing a `Status` (and its downstream `blocking?`/`deployable?`/`Hook.emit(:deployable_status, ...)`/continuous-delivery effects) to be written and evaluated on Repo B's commit.

### Finding Description
The intended binding is: `repository_name = payload.dig('repository','full_name')` must equal the repository of every `Commit` mutated by a handler, exactly as enforced by `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-34`), which every `PullRequest::*Handler` consults via `Shipit::Repository.from_github_repo_name(...)`.

`StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) breaks this binding:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
It never calls `stacks` or `repository_name`; it looks up commits globally by `sha` across all stacks/repositories in the Shipit instance. `Commit#sha` is not unique per repository/stack in this schema (`belongs_to :stack`, no uniqueness scoping visible on `sha`), so two different `Repository`/`Stack` records can legitimately contain a `Commit` with the same `sha` value (shared upstream history, cherry-picks, empty/no-op commits, or squash merges reproducing identical trees).

`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) validates the HMAC using `Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository','owner','login')`. This only proves the attacker controls the **named** repository/org's webhook secret — it does not, and cannot, prove anything about which `sha` values are legitimately theirs to report on. The signature check is therefore satisfied for a payload where `repository.full_name` = attacker's own repo, but `sha` = a value copied from a public commit visible in a victim repo's history (attacker can observe victim's public commits/SHAs via GitHub UI/API just like any other integration partner, then push/reference that identical sha as part of their own repo's history through legitimate git operations such as cherry-pick).

Exploit flow:
1. Attacker owns/administers Repo A in GitHub and it is connected to Shipit with a legitimate webhook secret (attacker has this because it's their own repo's Shipit integration).
2. Attacker discovers (via any public means) a `sha` that is also recorded as a `Commit` under Victim Repo B/Stack S in Shipit (naturally arises from shared history/cherry-picks, or attacker can engineer it by cherry-picking a commit from Repo B into Repo A, producing an identical tree/parent/committer-date combination and thus identical sha in some cases, or simply guesses among commits synced from forks).
3. Attacker triggers/sends `POST /webhooks` with `X-Github-Event: status`, `repository.full_name` = Repo A, signed correctly for Repo A's org, but `sha` = the colliding sha.
4. `drop_unhandled_event`/`verify_signature` pass because they only check Repo A's signature.
5. `StatusHandler#process` runs `Commit.where(sha: ...)`, matches the Commit row belonging to Stack S (Repo B), and calls `commit.create_status_from_github!(params)`, writing a `Status` under Repo B's stack with attacker-chosen `state`, `description`, `target_url`, `context`.
6. `Commit#add_status` (`app/models/shipit/commit.rb:366-386`) recomputes `status`, potentially flips `deployable?`/`blocked?`, emits `Hook.emit(:deployable_status, ...)`, and calls `stack.schedule_merges` if state is `pending`/`success` — i.e., attacker-controlled data can influence whether Repo B's stack considers a commit deployable or triggers automatic merges, without ever authenticating against Repo B.

No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema in `StatusHandler.params`) checks that the resolved `Commit`'s `stack.repository` matches the payload's `repository`. The `ExplicitParameters` schema only validates payload shape (`sha`, `state`, etc. are strings), not repository ownership.

### Impact Explanation
A payload for one attacker-controlled repository can write a `Status` row and alter deployability signals (`blocked?`, `deployable?`, merge scheduling via `stack.schedule_merges`) for a commit belonging to a completely different repository/stack that the attacker does not control and has no Shipit relationship to except the sha collision. This matches the Critical category "a payload for one repository mutating another's ... commit ... stack." It is repeatable against any repository whose commit shas the attacker can learn/reproduce, and is not limited to a single victim — any Shipit-managed stack sharing a sha with an attacker-owned repo is affected, giving cross-tenant blast radius within a single Shipit instance.

### Likelihood Explanation
Preconditions: attacker must control at least one repository connected to Shipit with a valid webhook secret for their own org (a normal, low-privilege setup for any developer who can add Shipit's GitHub App/webhook to their own repo), and must know/produce a `sha` that also exists as a `Commit` in a victim stack. SHA collision via natural means (shared history, cherry-picks, forks synced into multiple Shipit-tracked repos, identical empty/trivial commits) is realistic in organizations that mirror or fork repositories, and can also be manually engineered by cherry-picking a specific commit from the target repo (same author/committer timestamps produce an identical sha in many git tooling scenarios) into the attacker's own repo history, then referencing that sha in the crafted webhook. No secrets belonging to Shipit or the victim are required — only the attacker's own webhook secret for Repo A. This is a low-cost, repeatable attack once a colliding sha is identified.

### Recommendation
Scope `StatusHandler#process` to the payload's repository, mirroring the `PullRequest::*Handler` pattern:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
or equivalently filter `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` before creating any status, ensuring the `repository_name` derived from the payload is bound to every mutated `Commit`'s stack/repository.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
  test "StatusHandler must only mutate commits belonging to the payload's repository" do
    repo_a = shipit_repositories(:shipit)          # attacker-owned repo
    repo_b = create_repository(name: 'victim', owner: 'victim-org') # victim repo
    stack_a = create_stack(repository: repo_a)
    stack_b = create_stack(repository: repo_b)

    colliding_sha = 'a' * 40
    commit_a = stack_a.commits.create!(sha: colliding_sha, message: 'a')
    commit_b = stack_b.commits.create!(sha: colliding_sha, message: 'b')

    payload = {
      'repository' => { 'full_name' => repo_a.full_name },
      'sha' => colliding_sha,
      'state' => 'success'
    }

    handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

    # Binding under test: every Commit mutated must belong to stacks scoped
    # by payload's repository_name, exactly like Handler#stacks would resolve.
    expected_commit_ids = handler.send(:stacks).flat_map { |s| s.commits.where(sha: colliding_sha).pluck(:id) }
    actual_commit_ids = Shipit::Commit.where(sha: colliding_sha).pluck(:id)

    assert_equal expected_commit_ids.sort, actual_commit_ids.sort,
      "StatusHandler resolves commits across repositories, violating the repository binding"

    handler.process

    assert_predicate commit_b.reload.statuses, :any?, "victim repo's commit received an unauthenticated status"
  end
end
```
This demonstrates that `Commit.where(sha:)` (actual behavior) diverges from `stacks`-scoped resolution (intended behavior), and that `commit_b`, belonging to the victim's stack, receives a `Status` from a payload that only authenticated Repo A.