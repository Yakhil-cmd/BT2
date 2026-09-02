### Title
Cross-repository `status` webhook forgery lets an attacker satisfy CI requirements and advance another stack's merge queue - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` selects commits to update purely by `Commit.where(sha: params.sha)`, with no repository/stack scoping, and blindly writes a `Status` for every matching commit across the entire installation. Because `WebhooksController#verify_signature` only authenticates that *a* webhook came from a known GitHub organization/app installation - not that the SHA in the payload actually belongs to that organization's repository - an attacker who owns any repository (or fork) containing a commit with the same SHA as a commit in a victim's stack can push a `status` event for their own repo and have it applied to the victim's commit.

### Finding Description
The broken binding is: the code assumes `status.repository == commit.stack.repository` for every `Commit` row matching `params.sha`, but nothing enforces `params.dig('repository','full_name') == commit.stack.repo_name`.

Path:
- `Shipit::WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses the raw payload and dispatches to handlers after `verify_signature` (line 6, 24-49), which only checks `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This proves the HTTP request is a genuine GitHub webhook for *some* repository owned by `repository_owner` — it does not tie the `sha`/`context` inside the payload to that specific repository. [1](#0-0) 
- `StatusHandler#process` then does: [2](#0-1) 
which loops over `Commit.where(sha: params.sha)` **globally** (no stack/repo filter) and calls `commit.create_status_from_github!(params)` for every match.
- `Commit#create_status_from_github!` (app/models/shipit/commit.rb:165-169) calls `statuses.replicate_from_github!(stack_id, github_status)`, and `Status.replicate_from_github!` (app/models/shipit/status.rb:24-33) creates a `Status` row using only `state`/`description`/`target_url`/`context` from the payload — again with no repository check.
- Since git commit SHAs are content-addressed and identical commits (e.g. produced by forking a public target repository, or by any party who independently produces byte-identical commit content) yield identical SHAs regardless of which repository hosts them, an attacker can own a repository containing a commit whose SHA matches one already ingested into a victim stack (public repos' commit histories/shas are visible via GitHub itself and via the Shipit UI). The attacker sends (or triggers, e.g. via their own CI, using GitHub's normal status API) a `status` webhook from their own repository with `context` set to exactly the value the victim stack lists in `ci.require`, `sha` set to the shared SHA, and `state: "success"`.
- This webhook is legitimately signed by GitHub for the attacker's own repo/org, so `verify_signature` passes. `StatusHandler#process` then writes a passing `Status` onto the victim's `Commit` record (because the `WHERE sha = ...` query is unscoped), satisfying `MergeRequest#all_status_checks_passed?` / `Commit#deployable?` (app/models/shipit/commit.rb:227-229) which drives `Stack#schedule_merges` and eventual `merge!`.
- No other guard intercepts this: `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` (`params do ... end` block) only validates the shape of `sha`/`state`/`context`, not repository ownership; there is no `require_permission!`/`stacks` scope check in the webhook path at all, since webhooks are inherently unauthenticated except for the HMAC signature which is organization-scoped, not repository/SHA-scoped.

### Impact Explanation
An attacker who controls any GitHub repository (including a public fork of the victim project) can forge a passing CI status for a commit belonging to a stack they do not own, in a repository they do not control, causing that stack's merge/CI gating logic to treat the commit as deployable/mergeable. This is a cross-tenant integrity violation: a webhook authenticated for repository A mutates state (Commit/Status) belonging to repository B's stack, matching "a payload for one repository mutating another's stack, commit, task or team" and enabling "unauthorized deploy, rollback or merge" — Critical severity per the rubric.

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository/organization that Shipit's `GithubApp` recognizes (i.e., is installed/onboarded for) so that `verify_signature` succeeds for `repository_owner`; they also need a commit SHA identical to one already present in the victim's stack (trivially achievable by forking a public repository so its full commit history, and thus its exact SHAs, is reproduced in the attacker-owned repo) and knowledge of the exact `ci.require` context string used by the victim (visible in the repository's `shipit.yml`/deploy spec or Shipit UI). Given these, the attack is fully repeatable and requires no privileged Shipit role, API token, or secret — only the ability to emit a normal GitHub status event from a repository the attacker legitimately owns.

### Recommendation
Scope `StatusHandler#process` (and the analogous check-run handler if present) to commits whose owning stack's repository matches the webhook payload's `repository.full_name`/`repository.owner.login`, e.g. filter `Commit.where(sha: params.sha)` by joining `Stack` and comparing `repo_name`/`repo_owner` to `params.dig('repository', 'full_name')`, rejecting or ignoring statuses for commits that don't belong to the reporting repository.

### Proof of Concept
minitest plan (no live GitHub):
1. Create two `Shipit::Stack` records, `stack_a` (repo `victim/repo`) and `stack_b` (repo `attacker/fork`).
2. Create a `Shipit::Commit` under each stack with the identical `sha` value `"deadbeef" * 5` (simulate identical content-addressed commit reproduced via fork).
3. Configure `stack_a`'s deploy spec to require CI context `"ci/required"`.
4. Build a `status` payload: `{ sha: <shared_sha>, state: "success", context: "ci/required", repository: { full_name: "attacker/fork", owner: { login: "attacker" } } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)` (or `process`) directly (bypassing only the signature check, which is out of scope for this handler-level bug).
6. Assert: `stack_a.commits.find_by(sha: shared_sha).statuses.count == 1` and `.deployable?` becomes true — i.e., **repo `victim/repo`'s** commit CI state changed as a result of a webhook whose `repository.full_name` was `attacker/fork`, proving the equality `commit.stack.repo_name == payload['repository']['full_name']` is violated.
7. Assert `stack_a.schedule_merges`/`MergeRequest#all_status_checks_passed?` now returns `true` for the affected merge request, demonstrating the merge queue advanced due to a payload never authenticated for `victim/repo`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
