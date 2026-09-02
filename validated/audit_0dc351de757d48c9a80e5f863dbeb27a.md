### Title
`StatusHandler#process` resolves GitHub status webhooks by SHA alone, letting a webhook for repository A mutate a `Commit`/advance the deploy queue of an unrelated stack B - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)`, with no filter on the repository named in the webhook payload. Since `sha` is only unique per-stack (`index_commits_on_stack_id_and_sha`), not globally, a legitimately-signed status webhook from an attacker-owned repository can flip the status of a commit belonging to a completely different tenant's stack, causing `UndeployedCommit#deploy_disallowed?` to return `false` and the commit to become eligible for continuous deployment.

### Finding Description
The claimed binding is: `payload.repository.full_name == stack.repository.full_name` for the stack whose commit/deploy state is mutated. Tracing the code shows this binding is never enforced:

- `Shipit::WebhooksController#verify_signature` only validates that the payload was genuinely sent by GitHub for `repository_owner` (`params.dig('repository','owner','login')`), using `Shipit.github(organization: repository_owner)` [1](#0-0) . This proves authenticity of the *sender*, not that the `sha` in the payload is scoped to that sender's repository.
- `StatusHandler` schema only requires `sha`, `state`, etc.; it never requires or reads the payload's `repository` field [2](#0-1) .
- `process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . This query is global across every stack/repository in the database; it is not scoped by `stack_id` or by the payload's repository.
- The DB only has a `stack_id + sha` composite index (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming `sha` is not unique system-wide - the same SHA can legitimately exist for commits belonging to different stacks/repositories.
- `create_status_from_github!` creates a `Status` row on whatever `Commit` matched, and `Commit#status`/`Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) are recomputed from that status [4](#0-3) .
- `UndeployedCommit#deploy_disallowed?` is `!deployable? || !stack.deployable?` [5](#0-4) , so it directly inherits the effect of a status forged via an unrelated repository's webhook.

Exploit flow: attacker fetches the raw git commit object of a target commit in a victim's public/reachable repository (tree, parents, author/committer, timestamps, message are all public data), reconstructs a byte-identical commit object in a repository they own (git's object store is content-addressed and independent per-repo, so pushing an identical object yields an identical SHA), then triggers (or has their own CI emit) a `status` event with `state: "success"` on their own repo for that SHA. GitHub signs and delivers this webhook using the credentials for the attacker's own repository/organization, so `verify_signature` passes legitimately. `StatusHandler#process` then finds and mutates the victim's `Commit` row purely by SHA match, with no cross-check that it belongs to the repository named in the payload.

### Impact Explanation
A forged "success" status from an attacker-controlled repository writes a `Status` record onto another tenant's `Commit`, which can flip `Commit#deployable?` to `true` and thus `UndeployedCommit#deploy_disallowed?` to `false`. Combined with `expected_to_be_deployed?` and a stack with `continuous_deployment` enabled, this makes the forged commit eligible to become the next auto-deployed revision - i.e., a payload naming one repository mutates another repository's stack/commit/deploy state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). This is repeatable against any stack whose commit SHA the attacker can reproduce.

### Likelihood Explanation
The attacker needs: (1) a repository they own under an owner/org for which the Shipit instance's GitHub App/webhook secret is already configured (otherwise `verify_signature` raises `GithubOrganizationUnknown` and rejects with 422), and (2) the ability to reconstruct a byte-identical commit object of a target commit (feasible for any commit whose tree/parent/author/committer/timestamp/message metadata is knowable, e.g. via GitHub API on a public repo) and push it into their own repo. Both are achievable by an unprivileged GitHub user with no Shipit credentials, in any Shipit deployment serving multiple repositories/teams under a shared GitHub organization (a common multi-tenant Shipit deployment pattern). No secrets are required.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and similarly in `CheckSuiteHandler`/any other handler using bare SHA lookups) to the repository named in the webhook payload, e.g. resolve the target `Stack`(s) via `params.repository.full_name` first, then query `stack.commits.where(sha: params.sha)`, rejecting/ignoring statuses whose payload repository doesn't match the owning stack's repository.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` style, no live GitHub):
1. Create two stacks, `victim_stack` (repo `victim/repo`, `continuous_deployment: true`) and `attacker_stack` (repo `attacker/repo`).
2. Create a `Commit` under `victim_stack` with a fixed `sha` (e.g. `"deadbeef" * 5`) and no successful status yet; assert `UndeployedCommit.new(commit, index: 0).deploy_disallowed?` is `true` and it's absent from `victim_stack.commits.next_expected_commit_to_deploy`-derived undeployed list.
3. Build a `params` hash with the *same* `sha`, `state: "success"`, and (if included) a `repository` payload pointing at `attacker/repo`, matching what `StatusHandler` schema accepts.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new.call(params)` (bypassing controller-level signature check, which is out of scope since it only validates payload authenticity, not repository binding).
5. Assert the `Status` was created on the `victim_stack`'s `Commit` (`commit.reload.status.success?` is `true`) even though no payload field ties it to `victim/repo`.
6. Assert `UndeployedCommit.new(commit.reload, index: 0).deploy_disallowed?` is now `false`, demonstrating the binding `payload.repository == stack.repository` does not hold and the victim stack's queue was advanced by a foreign-repository webhook.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/undeployed_commit.rb (L39-41)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
    end
```
