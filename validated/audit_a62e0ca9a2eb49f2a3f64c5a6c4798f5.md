## Finding [1](#0-0) 

`StatusHandler#process` resolves target commits purely by SHA, with no scoping to the repository/organization that authenticated the webhook:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit.where(sha: params.sha)` queries **across every stack in the database**, not just commits belonging to the repository that signed the webhook. The webhook signature is verified per-organization in `WebhooksController#verify_signature` using `repository_owner` taken from the payload itself, and correctly confirms the request was genuinely signed by that organization's `webhook_secret`: [2](#0-1) 

That check only proves "org X really sent this status event for its own repo" — it does **not** bind the resulting `Commit.where(sha:)` lookup to org X's `Repository`/`Stack`. `Commit#create_status_from_github!` then writes a `Status` scoped to whichever stack owns the matching commit row (`statuses.replicate_from_github!(stack_id, github_status)`), regardless of which org's secret verified the request: [3](#0-2) 

### The broken binding
Claimed binding: `organization_that_verified_signature == organization_owning_stack.repository`.
Actual code: the binding only holds at the controller layer (`Shipit.github(organization: repository_owner)`); it is never propagated into `StatusHandler#process`'s `Commit.where(sha:)` query, so a genuinely-signed status from org X's own repo can attach a `Status` to a `Commit` belonging to org Y's stack whenever the two commits share a SHA.

### Exploit path
1. Shipit is configured (per `docs/setup.md`, "Using Multiple GitHub Applications") to serve multiple orgs, each with its own `webhook_secret` — org X and org Y are both legitimate tenants of the same Shipit instance.
2. Org Y's stack has already synced (via `GithubSyncJob`) a specific commit with SHA `S` that is currently blocked (`Commit#deployable?` false, e.g. failing/absent CI status).
3. The attacker, who owns a repository under org X, crafts a git commit object with identical tree/parent/author/committer/message/timestamps as commit `S` in org Y's repo, producing the exact same SHA-1, and pushes it to their own org X repository.
4. The attacker (as the owner/admin of their own org X repo) sets a commit status (`state: success`) for that SHA via the GitHub Status API on their own repo. GitHub delivers a genuinely `X-Hub-Signature`-signed `status` webhook using org X's real `webhook_secret`.
5. `WebhooksController#verify_signature` succeeds (org X's secret correctly verifies org X's event).
6. `StatusHandler#process` runs `Commit.where(sha: S)`, which also matches org Y's `Commit` row, and calls `create_status_from_github!`, writing a `Status` with `stack_id` = org Y's stack.
7. `Commit#deployable?` for org Y's commit now flips to `true` purely off the forged Status.
8. `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` (scoped to org Y's own `commits`, via `has_many :commits`) selects this commit and calls `trigger_deploy(commit, Shipit.user, ...)` → `Deploy#enqueue`, deploying org Y's stack using org Y's credentials/host, triggered entirely by org X's webhook.

None of the existing guards prevent this: `verify_signature` validates org X's own signature correctly (it's not being bypassed — it's simply the wrong scope of trust boundary), `drop_unhandled_event` allows `status`, and the `ExplicitParameters` schema for `StatusHandler` (`sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`) never includes or checks `repository`/`full_name`, so nothing in the handler enforces that the matched `Commit#stack` belongs to the org that sent the request.

### Title
Cross-tenant Status forgery via unscoped SHA lookup in `StatusHandler#process` leads to unauthorized deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` matches commits by SHA alone (`Commit.where(sha: params.sha)`) without verifying that the matched commit's stack/repository belongs to the organization that authenticated the webhook. A webhook genuinely signed by org X's `webhook_secret` can therefore write a `Status` onto a `Commit` belonging to org Y's stack whenever the two share an identical SHA, which can be engineered by reproducing an existing target commit's exact git metadata in an attacker-controlled repository.

### Finding Description
The intended binding — "the organization whose `webhook_secret` verified this request owns the repository/stack the Status is written to" — is enforced at the controller level (`WebhooksController#verify_signature`, using `Shipit.github(organization: repository_owner)`) but is silently dropped inside `StatusHandler#process`, which performs a global, unscoped `Commit.where(sha:)` lookup and calls `commit.create_status_from_github!` on every match, writing to whichever `stack_id` that commit row happens to carry. See `app/controllers/shipit/webhooks_controller.rb:24-30`, `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, and `app/models/shipit/commit.rb:165-169`. Since Shipit's `Commit` table has no per-stack uniqueness constraint precluding identical SHAs in unrelated stacks (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb` is a composite index, not a global uniqueness guarantee), an attacker who legitimately owns a repository in a different, co-tenant organization (org X) can forge a commit with a colliding SHA and post a genuinely-signed `status` webhook for it, causing a `Status` to be attached to org Y's unrelated `Commit`. This flips `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) for org Y's blocked commit, and `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` → `trigger_deploy` (`app/models/shipit/stack.rb:210-243`) deploys it using org Y's own credentials/host.

### Impact Explanation
An unprivileged attacker who controls any repository configured on the same multi-tenant Shipit instance can trigger an unauthorized deploy on a completely unrelated organization's stack, using that victim's deploy commands/credentials, without ever needing org Y's `webhook_secret`, session, or API token. This is repeatable against any stack whose next undeployed commit's SHA the attacker can reproduce, and the blast radius spans tenant boundaries within a single shared Shipit deployment — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy."

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit setup with more than one configured GitHub organization (explicitly documented and supported), (2) the attacker being able to fabricate a git commit object with identical tree/parent/author/committer/timestamps/message as a target commit already synced into the victim stack (feasible when the target commit or its full metadata is publicly known, e.g. open-source mirrors, or otherwise obtainable), and (3) the ability to post a status for that SHA on their own repository (trivial for any repo owner via GitHub's Status API). No Shipit secrets are needed. Given these preconditions, exploitation is a single crafted webhook per attempt and fully repeatable.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers using bare SHA lookups) to the repository identified in the webhook payload, e.g. resolve the `Stack`/`Repository` from `params.dig('repository', 'full_name')` first and constrain `Commit.where(sha: params.sha, stack: matching_stacks)` before calling `create_status_from_github!`, rather than matching SHAs globally across all tenants.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb` style, no live GitHub):
1. Create `stack_x` owned by `Repository(owner: 'org-x', ...)` and `stack_y` owned by `Repository(owner: 'org-y', ...)`, both with `cached_deploy_spec` present and `continuous_deployment: true` for `stack_y`.
2. Create `Commit.create!(stack: stack_y, sha: 'deadbeef...', ...)` that is currently non-deployable (no successful status), representing the next commit to deploy for `stack_y` (assert `stack_y.next_commit_to_deploy` is `nil` or not this commit before the forged status).
3. Also create `Commit.create!(stack: stack_x, sha: 'deadbeef...', ...)` (same SHA, org X's own tracked commit).
4. Stub `GithubHook`/`verify_signature` (or `Shipit.github(organization: 'org-x')`) to simulate a genuinely signed `status` event for org X, with `sha: 'deadbeef...', state: 'success'`.
5. POST the status webhook to `/webhooks` with `X-Github-Event: status` and org-x repository info.
6. Assert `stack_y.commits.find_by(sha: 'deadbeef...').statuses.count` increased and `commit.reload.deployable?` is now `true` — i.e., a Status was written to `stack_y` from an org-x-signed event.
7. Run `stack_y.trigger_continuous_delivery` (or enqueue `ContinuousDeliveryJob`) and `assert_difference('Deploy.where(stack: stack_y).count', 1)`, proving org Y's stack was deployed as a result of org X's webhook.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
