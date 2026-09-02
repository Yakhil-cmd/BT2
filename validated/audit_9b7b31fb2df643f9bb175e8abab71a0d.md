### Title
Cross-repository status forgery via unscoped SHA lookup breaks organization-signature-to-repository binding - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The webhook signature verification authenticates the *organization* that owns the payload's `repository.owner.login` [1](#0-0) [2](#0-1) , but `StatusHandler#process` writes a CI status to any `Commit` in the entire Shipit installation whose SHA matches the payload's `sha`, with no check that the commit belongs to a repository owned by the signing organization [3](#0-2) . Unlike every other handler (`PushHandler`, `PullRequest::*Handler`), which resolve the target through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any record [4](#0-3) [5](#0-4) , `StatusHandler` never resolves or checks `repository`/`stacks` at all — it is the sole handler that binds the signature check to one identity (organization/repository owner) while performing its write keyed only by a global SHA lookup.

### Finding Description
The trust chain is:
1. `WebhooksController#verify_signature` determines which organization's webhook secret to validate against using `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) .
2. This only proves the payload was genuinely sent by GitHub *for that organization's own installation* — it says nothing about which repository's commits may be mutated.
3. `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This looks up commits **globally by SHA across all stacks/repositories tracked by the entire Shipit instance**, and `create_status_from_github!` creates the `Status` scoped to `commit.stack_id` — i.e., whatever stack that pre-existing `Commit` row actually belongs to, regardless of which organization/repository signed the incoming webhook [6](#0-5) .

Because git commit objects are content-addressed (SHA-1 over tree, parents, author/committer, message), an attacker who controls a repository/organization with the Shipit GitHub App installed (a normal, unprivileged tenant of the same Shipit instance) can:
- Reconstruct an existing public commit from a *different*, unrelated tracked repository (same tree/parents/timestamps/message) inside their own repository, producing an identical SHA.
- Post/have GitHub post a genuine, correctly-signed `status` webhook for their own org (e.g. via a CI integration or the Statuses API on their own repo) with `state: "success"` for that SHA.
- Because `verify_signature` only checks that this event was legitimately signed by *the attacker's own organization*, it passes.
- `StatusHandler` then finds the *victim's* pre-existing `Commit` row (same SHA, different stack) and writes a forged "success" status to it, attributed to the victim's stack.

This directly parallels the M-14 bug class: one code path verifies a binding using field A (`epochBegin`/organization-owner) while a different code path acts using field B (`finalTVL`-eligibility/commit SHA scoped to no repository), letting an attacker satisfy the check on one identity while the effect lands on another.

### Impact Explanation
A forged "success" (or any) status on a victim's commit:
- Sets `Commit#status` state, which feeds `MergeRequest#all_status_checks_passed?`/`any_status_checks_failed?` via `StatusChecker` [7](#0-6) , allowing the merge queue to consider a PR CI-green and merge it (`allows_merges?`/`merge!`) even though the real CI never ran/passed on that repository — an **unauthorized merge**.
- Triggers `stack.schedule_merges` and continuous delivery scheduling on success/pending transitions (`add_status`) [8](#0-7) , which can queue an **unauthorized deploy** on a stack with `continuous_deployment` enabled.
- Requires no privileged Shipit credentials, `ApiClient` token, or repository write access on the *victim* repository — only ordinary access to any other repository/org already onboarded to the same Shipit instance, i.e., an unprivileged cross-tenant attacker.

This satisfies the Critical bar: "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitation requires: (a) the attacker's own organization/repo already has the Shipit GitHub App/webhook installed (normal tenant onboarding, not a privilege escalation), and (b) the ability to reproduce an existing target commit's exact SHA and get GitHub to emit a `status` event for it. Reconstructing a byte-identical git commit for a known SHA from a public repository (copying tree/parents/author/committer/message/timestamps) is mechanical and requires no cryptographic break — SHA-1 collision is not needed, only *replaying* the same commit content, which is always possible for any commit whose full metadata is public. This makes the likelihood **medium** in a genuinely multi-tenant Shipit deployment (the documented normal deployment mode), though it depends on Shipit hosting multiple independent organizations/repos and the target commit being publicly reproducible.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve `repository`/`stacks` from `payload.dig('repository','full_name')` (as `Handler#stacks` already provides [4](#0-3) ) and restrict the `Commit.where(sha: params.sha)` lookup to `commit.stack_id IN stacks.pluck(:id)` (or `stacks.commits.where(sha:)`), rejecting/ignoring statuses whose SHA belongs to a stack outside the signing organization's own repositories.

### Proof of Concept
1. Attacker's organization `org-attacker` has the Shipit GitHub App installed on `org-attacker/decoy-repo` (legitimate onboarding as any Shipit tenant).
2. Victim organization `org-victim` has a public repository `org-victim/prod-repo` tracked by Shipit, with commit `abc123...` (SHA known/public) currently pending/failing CI.
3. Attacker reconstructs the exact same git commit object (identical tree, parent, author/committer identities and timestamps, message) inside `org-attacker/decoy-repo`, producing SHA `abc123...`, and pushes/loads it so it's reachable in their repo.
4. Attacker posts a Status (`state: success`) for `abc123...` on `org-attacker/decoy-repo` via the GitHub Statuses API (their own repo, their own permission).
5. GitHub sends a `status` webhook to Shipit's `WebhooksController#create`, signed with `org-attacker`'s webhook secret and `repository.owner.login == "org-attacker"`.
6. `verify_signature` validates successfully against `org-attacker`'s secret.
7. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, matches the `org-victim/prod-repo` commit row, and calls `create_status_from_github!`, writing `state: success` into `org-victim`'s stack.
8. `org-victim`'s stack now shows the commit as CI-passing, enabling `schedule_merges`/continuous delivery to proceed as if real CI succeeded — an unauthorized deploy/merge on `org-victim`'s stack triggered entirely by `org-attacker`'s own signed webhook.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
