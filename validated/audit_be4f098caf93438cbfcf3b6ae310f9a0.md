### Title
`StatusHandler#process` updates commit statuses across all stacks sharing a `sha`, bypassing `Handler#repository_name`/`#stacks` scoping - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` queries `Commit.where(sha: params.sha)` globally and calls `create_status_from_github!` on every match, without ever calling `Handler#repository_name` or `Handler#stacks` to constrain the query to the repository that produced the webhook. Since `Commit` rows belong to individual `Stack`s and the same git commit SHA can legitimately exist in more than one tracked stack (e.g. a fork of a tracked repository), an attacker who owns any repository tracked by Shipit can forge a `status` event that writes a commit status onto a *different* stack's identical-SHA commit.

### Finding Description
The claimed binding is: `Handler#repository_name` / `Handler#stacks` availability == its actual use inside `StatusHandler#process`. Tracing the code confirms this binding is broken:

- `app/controllers/shipit/webhooks_controller.rb:11-12` parses the raw JSON body into `params` and calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the full, unscoped payload.
- `app/models/shipit/webhooks/handlers/handler.rb:15-24` shows `Handler.call` builds `new(payload)`, storing `@payload` and parsing typed `@params`. `repository_name` (line 36-38) reads `payload.dig('repository', 'full_name')` and `stacks` (line 32-34) resolves `Repository.from_github_repo_name(repository_name)&.stacks`. These are available to every subclass.
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` implements `process` as:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This never references `repository_name` or `stacks`. `Commit` records are scoped to a `Stack`, and multiple stacks (tracking different but related GitHub repositories, e.g. a fork) can contain a `Commit` row with the identical `sha`, since git commit hashes are content-addressed and are preserved verbatim when a repository is forked without rewriting history. `verify_signature` (`webhooks_controller.rb:24-49`) only proves the payload was sent by (or on behalf of) the organization named in `payload['repository']['owner']['login']`/`organization.login` — it authenticates *which org sent this request*, not *which stack's commits may be mutated*. It does nothing to scope the subsequent `Commit.where(sha: ...)` query. `drop_unhandled_event` and the `ExplicitParameters` schema only validate that required fields (`sha`, `state`) are present/typed; they do not scope the query either.

Attack flow: an attacker forks a public repository that Shipit also tracks under a different (victim) stack, or otherwise controls a repository whose GitHub App/webhook secret they legitimately hold for their own org. They push (or already have) a commit whose SHA is identical to a commit in the victim's tracked stack (trivial via forking, since forking doesn't alter git object hashes). They then trigger (or directly POST) a `status` webhook for their own repository with that shared `sha` and an arbitrary `state`/`context`/`description`. `verify_signature` succeeds because it's signed for the attacker's own org. `StatusHandler#process` then finds **all** `Commit` rows across **all** stacks with that `sha` — including the victim's — and writes the forged status via `commit.create_status_from_github!(params)`.

### Impact Explanation
A forged commit status written onto a victim stack's commit can flip `Commit#state`/`deployable?`, which feeds `Stack#branch_status`, `Stack#merge_status`, `Stack#allows_merges?`, and `UndeployedCommit#deployable?`/`#deploy_disallowed?` (`app/models/shipit/stack.rb:286-382`, `app/models/shipit/undeployed_commit.rb:18-41`). If a victim stack has `merge_queue_enabled?` or continuous deployment, an attacker-forged "success" status can make an otherwise non-deployable/non-mergeable commit appear deployable/mergeable, enabling an unauthorized deploy or merge on a repository/stack the attacker never authenticated against. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitability requires: (1) the attacker's own repository/org must already be onboarded to Shipit (so their webhook signature verifies), and (2) a commit SHA collision with a commit already tracked in the victim stack — trivially achievable by forking a public GitHub repository the victim also has Shipit tracking, since git object hashes are preserved across forks without any rewrite. No GitHub/Shipit secrets, sessions, or elevated roles are needed beyond owning/administering one tracked repository and being able to fire a webhook (or push a commit that triggers CI to post a status) for it. This is repeatable against any stack whose commit history overlaps (via fork ancestry) with a repository the attacker controls.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries `Commit`/model records globally by payload-derived identifiers) to the stacks resolved from `Handler#stacks`/`repository_name`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status update can never cross repository/stack boundaries even when SHAs coincide.

### Proof of Concept
```ruby
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "process never calls Handler#stacks/#repository_name and updates commits across stacks sharing a sha" do
          victim_stack = shipit_stacks(:shipit)
          attacker_stack = shipit_stacks(:cyclimse) # different stack/repository fixture

          shared_sha = 'a' * 40
          victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_authors(:cyclimse), message: 'x')
          attacker_commit = attacker_stack.commits.create!(sha: shared_sha, author: shipit_authors(:cyclimse), message: 'x')

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => attacker_stack.repository.full_name },
          }

          # Binding under test: Handler#stacks / #repository_name must be invoked to scope the write.
          Handler.any_instance.expects(:stacks).never
          Handler.any_instance.expects(:repository_name).never

          assert_difference -> { victim_commit.reload.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          # Proves cross-repo write: attacker's payload (signed/scoped to attacker_stack's repo)
          # mutated victim_stack's commit status despite never calling the scoping primitive.
          assert_equal 'success', victim_commit.reload.state
        end
      end
    end
  end
end
```
This demonstrates that `Handler#stacks`/`#repository_name` are dead code with respect to `StatusHandler#process`, and that a same-shape payload for one repository writes a status onto a commit belonging to an unrelated stack.