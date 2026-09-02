### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository/stack claimed in the payload or authenticated by the webhook signature. Any attacker who controls a legitimately signed webhook for their own onboarded repository can forge a `status` event whose `sha` matches a commit that also exists in a victim's stack (trivially true for forked repositories, which share ancestor commit shas because git shas are content hashes), causing the victim's commit status to be mutated.

### Finding Description
The broken binding is: `payload.repository (the org/repo the signature authenticates)` MUST equal `commit.stack.repository (the stack whose Commit row gets mutated)`. This equality is never checked.

- `WebhooksController#verify_signature` only proves the payload was legitimately signed for the org named in `payload['repository']['owner']['login']` (`app/controllers/shipit/webhooks_controller.rb:24-30`, `:59-62`). It authenticates *who sent the payload*, not *which stack the sha belongs to*.
- `StatusHandler` declares `accepts :branches` as pure descriptive metadata (`app/models/shipit/webhooks/handlers/status_handler.rb:15-17`) and `#process` never reads `branches` or `repository`; it only does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
(`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`)
- `Commit belongs_to :stack` (`app/models/shipit/commit.rb:11`) and `sha` is not required to be globally unique across stacks — it is only used for lookup here with no `stack_id`/`repository` filter.

Exploit flow: an attacker who owns a repository already onboarded to Shipit (so `Shipit.github(organization: repository_owner)` resolves and `verify_signature` succeeds for their own org) forks or otherwise shares history with the victim's repository. Any commit sha that is common to both repos (all ancestor commits prior to the fork point, or a cherry-picked/backported commit, share byte-identical git objects and therefore identical shas — this requires no cryptographic collision, only ordinary git history reuse). The attacker triggers (or crafts) a `status` webhook from their own repo naming that shared sha, optionally including `branches: [{name: 'main'}]` to make the payload look like it targets the victim's `main` branch. `verify_signature` passes because the signature is genuinely valid for the attacker's own org. `StatusHandler#process` then matches and mutates **every** `Commit` row across **all stacks** sharing that sha, including the victim's `main`-branch commit, via `create_status_from_github!`, which writes a new `Status` and can flip `deployable?`/`blocked?` results (`app/models/shipit/commit.rb:227-237`) and trigger `stack.schedule_merges` (`app/models/shipit/commit.rb:383`).

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate the sender's identity and payload shape — none of them re-check that the sha being mutated actually belongs to the stack the sender is authorized for.

### Impact Explanation
An attacker with a legitimately signed webhook for their own onboarded repository can write a forged `Status` (e.g., `state: "success"`) onto a commit belonging to an unrelated victim stack, provided the two repositories share a commit sha (common in forks). This satisfies the Critical category "a payload for one repository mutating another's stack, commit, task or team" — it can flip a commit from blocked/pending to `deployable?` and trigger automatic merges/deploys via `stack.schedule_merges` (`app/models/shipit/commit.rb:383`) on a repository the attacker never authenticated against. The attack is repeatable against any victim stack that shares ancestor commits with an attacker-controlled repository (any fork relationship), and is not limited to a single request.

### Likelihood Explanation
Requires: (1) attacker has at least one repository already registered as a Shipit stack (self-service onboarding, no special privilege beyond owning a repo/org known to `Shipit.github`), and (2) the victim stack shares a commit sha with the attacker's repository — true for any public fork or any repo with common history/cherry-picks. No cryptographic sha collision computation is needed; git shas are content-addressed, so shared history yields identical shas naturally. This makes the precondition realistic and not merely theoretical, though it is bounded to repositories with shared git history rather than arbitrary unrelated repositories.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any sibling handlers with the same pattern) to the repository asserted by the authenticated webhook, e.g. join through `stack.repository` matching `params.dig('repository', 'full_name')`/`repository_owner`, or otherwise ensure the commit's stack belongs to the same GitHub repository that the verified webhook signature was issued for, before applying `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook mutates commits across stacks when sha matches" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, message: 'shared ancestor commit')

  attacker_stack = Shipit::Stack.create!(repository: shipit_repositories(:other), branch: 'main')
  # attacker's own repo legitimately contains the same sha (shared history / fork)
  attacker_stack.commits.create!(sha: 'a' * 40, message: 'same commit, different repo')

  payload = {
    'sha' => 'a' * 40,
    'state' => 'success',
    'context' => 'ci/forged',
    'branches' => [{ 'name' => 'main' }],
    'repository' => { 'full_name' => attacker_stack.repository.full_name }
  }

  # binding under test, before mutation:
  assert_not_equal victim_stack.repository.full_name, payload['repository']['full_name']

  Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)

  victim_commit.reload
  # binding is broken: victim commit mutated by a payload naming attacker's repository
  assert_equal 'success', victim_commit.status.state
end
```