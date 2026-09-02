### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a GitHub `status` webhook against the `webhook_secret` of the organization that *owns the delivering repository* [1](#0-0) , but `StatusHandler#process` never re-checks that the commit SHA in the verified payload actually belongs to that same organization/repository — it looks the commit up by SHA alone across the entire Shipit database [2](#0-1) . This breaks the equality: `organization that authenticated == repository whose commit is written`.

### Finding Description
Every other event handler that mutates state scopes its effect to the repository named in the verified payload:
- `PushHandler` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` before touching any stack [3](#0-2) .
- `CheckSuiteHandler` likewise filters through `stacks` (repository-scoped) before matching `head_sha` [4](#0-3) .
- The base `Handler#stacks` helper explicitly derives the resolution key from `payload.dig('repository', 'full_name')` [5](#0-4) .

`StatusHandler`, however, ignores `repository_name`/`stacks` entirely and queries commits globally:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`verify_signature` in the controller only proves that *some* organization (identified by `repository_owner`, taken from `params.dig('repository','owner','login')`) legitimately signed this specific delivery [6](#0-5) . It says nothing about which commit SHAs that organization is entitled to affect. Because `Commit` rows are global (not namespaced per organization in this lookup) and git commit SHAs are simply 40-hex identifiers that are entirely attacker-controllable when creating a commit status via the GitHub API (`POST /repos/{owner}/{repo}/statuses/{sha}`), any organization/repository that has Shipit's GitHub App installed can emit a validly-signed `status` webhook whose `sha` field names a commit that is tracked under a *different* organization's stack in the same Shipit instance — as long as that git commit object also exists (or can be referenced) in the attacker's own repository, which is trivially true for any commit reachable through a public fork, a shared history, or simply a commit the attacker mirrors/copies via `git fetch`/`git push` into a repo they administer.

### Impact Explanation
Commit statuses drive Shipit's deploy-readiness/CI gates (`ci.require`, `ci.blocking`, merge-queue validation) described in `README.md`'s CI/Merge Queue sections. A forged "success" status written onto a victim organization's commit via `Commit#create_status_from_github!` can clear a CI gate the victim never actually passed, enabling an unauthorized/premature deploy or merge on a stack the attacker has no legitimate relationship with — a cross-tenant, cross-repository write satisfying the "Critical: cross-repository writes / unauthorized deploy" impact bar.

### Likelihood Explanation
The attacker needs only: (1) their own repository/organization onboarded to the shared Shipit instance with a working GitHub App webhook (a completely unprivileged, normal customer/organization relationship — no `ApiClient` token, no `webhook_secret`, no GitHub App key, no victim repo access needed), and (2) knowledge of a target commit SHA from a different tracked repository, which is often discoverable from public commit history, Shipit's own UI (stack/commit pages, permalinks referenced in README's `SHIPIT_LINK`), or shared/forked repositories. No interaction with the victim organization is required.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve the commit through `stacks` (i.e., `Repository.from_github_repo_name(repository_name)`-derived stacks) rather than a bare, unscoped `Commit.where(sha: params.sha)`, so a verified webhook can only mutate commits that belong to the repository named (and authenticated) in that same payload.

### Proof of Concept
1. Attacker controls (or legitimately administers) `attacker-org/attacker-repo`, which is installed with Shipit's GitHub App (valid `webhook_secret` for `attacker-org`).
2. Attacker obtains the git commit SHA `S` of a commit tracked by `victim-org/victim-repo`'s Shipit stack (e.g., from a public fork, shared upstream history, or the Shipit UI).
3. Attacker fetches/creates that same commit object `S` inside `attacker-repo` (git object IDs are content-addressed and portable) and calls the GitHub REST API `POST /repos/attacker-org/attacker-repo/statuses/S` with `state: success`, using only normal collaborator/CI permissions on their own repo.
4. GitHub sends a `status` webhook, correctly HMAC-signed with `attacker-org`'s webhook secret, to Shipit.
5. `WebhooksController#verify_signature` succeeds (signature matches `attacker-org`'s secret) [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: S)`, finds the commit belonging to `victim-org/victim-repo`'s stack, and calls `create_status_from_github!`, writing a forged CI status onto the victim's commit [2](#0-1) .

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-16)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
