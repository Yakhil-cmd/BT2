This confirms the finding: `Commit.where(sha: params.sha)` in `StatusHandler#process` performs a **global, cross-repository lookup by SHA alone**, with no comparison against the repository that the webhook payload claims to be from, and no comparison against the `stack`/`repository` the matched `Commit` belongs to. The webhook-signature check in `WebhooksController#verify_signature` only authenticates that the *organization* named in the payload owns a valid `webhook_secret` — it never verifies that the payload's `repository.full_name` matches the `Commit#stack.repository`. Since GitHub SHAs are content-addressed, an attacker who can reproduce the exact same commit content (tree, parents, author/committer identity and timestamps, message) in a repository they control can obtain an identical SHA to a commit already tracked by Shipit for a different stack.### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized PR merge - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by SHA alone, with no check that the webhook's `repository.full_name` matches the `stack`/`Repository` the matched `Commit` belongs to, even though the base `Handler` class already provides a `stacks`/`repository_name` scoping mechanism that other handlers use. Because GitHub SHAs are content-addressed, an attacker can reproduce an identical SHA in a repository they control, send a signed `status` webhook from that repository, and have the resulting `Status` attached to the real `Commit` on a completely unrelated stack, driving `MergeRequest#all_status_checks_passed?` to `true` and triggering an unauthorized `merge_pull_request` call on the victim repository.

### Finding Description
The claimed binding is: `repository_from_webhook_signature(B) == repository_of(Stack/MergeRequest being merged)(A)`. Tracing the code shows this equality is never enforced for the `status` event.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that the HMAC signature is valid for the *organization* derived from `params.dig('repository','owner','login')` against `Shipit.github(organization: repository_owner).webhook_secret`. Per `docs/setup.md` and `lib/shipit.rb#github`, this secret is configured **per-organization** (or globally, in the single-app config), not per-repository. Any repository under that same GitHub App installation/org authenticates with the same secret.
- The base `Handlers::Handler` class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) exposes a `stacks` helper that scopes lookups via `Repository.from_github_repo_name(repository_name)&.stacks`, i.e., it is the engine's own mechanism for tying webhook processing back to the repository that sent the payload.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does **not** use this scoping. It does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global, unscoped lookup across every `Commit` row in the database, regardless of which `stack`/`Repository` owns it.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) unconditionally records the status via `statuses.replicate_from_github!(stack_id, github_status)`.
- `MergeRequest#all_status_checks_passed?` (`app/models/shipit/merge_request.rb:193-197`) evaluates `StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?` purely from the `Status` rows attached to the `head` commit — with no re-validation of which repository produced those statuses.
- `ProcessMergeRequestsJob#perform` (`app/jobs/shipit/process_merge_requests_job.rb:21-26`) calls `merge_request.merge!` once `all_status_checks_passed?` is true, and `MergeRequest#merge!` (`app/models/shipit/merge_request.rb:164-191`) calls `stack.github_api.merge_pull_request(stack.github_repo_name, number, ...)` — merging on **stack A's** repository using stack A's app credentials.

Exploit flow: attacker pushes a commit with identical tree/parent/author/committer/timestamp/message to a repository B they control under the same GitHub org/app installation as stack A (or under the org whose webhook_secret they can trivially satisfy in a single-secret deployment), obtaining the same SHA as stack A's pending `MergeRequest#head`. Attacker (or GitHub, upon any status change on repo B) triggers a `status` webhook with `state: success` and that SHA, signed with B's org's real `webhook_secret`. `verify_signature` passes because the signature is valid for that org/secret — it never checks that repo B equals repo A. `StatusHandler` finds the shared-SHA `Commit` row belonging to stack A and attaches the forged success status to it. On the next `ProcessMergeRequestsJob` run, `all_status_checks_passed?` returns true and `merge!` is invoked against stack A's real repository via `Shipit.github.api`.

Existing guards fail because: `verify_signature` authenticates at the org/app-secret level, not the repository level; `drop_unhandled_event`/`ExplicitParameters` only validate payload shape (`sha`, `state`, etc.), not repository identity; and unlike other handlers, `StatusHandler` does not use the `stacks`/`repository_name` scoping already present in the base `Handler` class.

### Impact Explanation
Successful exploitation causes Shipit to call GitHub's merge API (`stack.github_api.merge_pull_request`) on a repository (A) that the attacker never had write access to and that never sent the authenticating webhook, resulting in an unauthorized merge of a pull request. This is a "payload for one repository mutating another's stack" — matching the Critical severity category explicitly listed (unauthorized merge). Blast radius spans every stack sharing the same GitHub App/organization webhook secret, i.e., potentially many tenant repositories under one installation, and is repeatable per pending merge request since the attacker only needs to reproduce a matching SHA and fire one webhook per target commit.

### Likelihood Explanation
Preconditions: a target stack must have an open `MergeRequest` in `pending` status (a normal, common merge-queue state), and the attacker must control a repository under the same GitHub App installation/organization as the target (satisfied automatically in the common single-webhook-secret configuration described in `docs/setup.md`, or when the attacker's own org/repo shares the app in the multi-org config). Reproducing an identical commit SHA is straightforward for public repositories or PRs with known commit metadata (git SHAs are deterministic hashes of tree+parent+author+committer+timestamps+message, all attacker-controllable when authoring their own commit against the same base). Cost is low: no session, token, or secret is required beyond ordinary GitHub push/webhook access to a repo the attacker owns. It is repeatable against any stack/pending MR whose head SHA the attacker can reproduce.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository asserted by the webhook payload, mirroring the base `Handler#stacks` helper, e.g. restrict to commits belonging to stacks whose `Repository` matches `payload.dig('repository', 'full_name')` before calling `create_status_from_github!`. Reject or ignore status events whose payload repository does not match the `Commit`'s own `stack.repository`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "cross-repository status webhook cannot flip merge checks for a stack it doesn't belong to" do
          stack_a = shipit_stacks(:shipit) # repository A
          commit = stack_a.commits.create!(sha: 'deadbeef' * 5, message: '...')
          merge_request = shipit_merge_requests(:pending) # belongs to stack_a, head: commit
          merge_request.update!(head: commit)

          # Attacker's payload claims repository B, but sha collides with stack A's head commit
          payload = {
            'sha' => commit.sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
          }

          assert_no_difference -> { commit.statuses.count } do
            StatusHandler.call(payload)
          end

          refute merge_request.reload.all_status_checks_passed?
        end
      end
    end
  end
end
```
This test currently **fails** against the existing `StatusHandler#process`, because `Commit.where(sha: params.sha)` matches `commit` regardless of the payload's `repository.full_name`, proving the cross-repository status forgery and the downstream `all_status_checks_passed?`/`merge!` risk.