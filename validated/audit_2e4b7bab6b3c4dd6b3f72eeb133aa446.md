### Title
Cross-repository CI status forgery via unscoped SHA lookup in StatusHandler - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to update purely by `sha`, without scoping the query to the repository the inbound webhook was authenticated for. Every other handler in the same directory (e.g. `PushHandler`) narrows its side effects to the `stacks` derived from the webhook's own `repository.full_name` before acting, but `StatusHandler` does not.

### Finding Description
The webhook signature check binds "the organization that authenticated" to a specific `GitHubApp` config, selected via the payload's own `repository`/`organization` login: [1](#0-0) [2](#0-1) 

That verification only proves the payload was sent by an account/app that owns *some* repository whose webhook secret matches — it says nothing about which `Commit` rows may be mutated. `Handler#stacks` exists precisely to constrain effects to the repository named in the payload: [3](#0-2) 

`PushHandler` uses this scoping correctly, restricting its update to stacks belonging to the payload's own repository: [4](#0-3) 

`StatusHandler`, however, never calls `stacks` or otherwise checks `repository_name`. It resolves target commits by SHA alone, across the entire `commits` table, and writes a CI status onto every match: [5](#0-4) 

Git commit SHAs are content-addressed but not unique to one repository: the same SHA can legitimately exist in two independently tracked Shipit stacks (forks, mirrors, monorepo splits, or simply a commit copied verbatim between repos with identical author/committer/timestamp/tree). This breaks the intended binding:

`organization authenticated by webhook signature (repository the attacker controls)` ≠ `repository whose Commit row is written (any stack containing that SHA)`

An attacker who administers or can add the GitHub App/webhook to any repository (their own, low-privilege, unrelated repository) can legitimately trigger a signed "status" webhook for that repository, but supply an arbitrary `sha` value that happens to match a commit tracked under a completely different, higher-privilege stack. `StatusHandler` will happily attach the forged status (e.g. `state: success`, arbitrary `context`) to that unrelated commit.

### Impact Explanation
Shipit's deploy/merge safety gates (required statuses, blocking statuses, merge-queue CI requirements — see CHANGELOG entries on "Reject commits with missing statuses from the merge queue" and "blocking statuses… prevent deploy") are driven by `Commit#statuses`. Forging a passing status on a commit belonging to a stack the attacker has no access to can satisfy those gates and enable an **unauthorized deploy or merge** on a repository the attacker does not control — the impact class explicitly listed as Critical.

### Likelihood Explanation
This requires: (1) control of any repository with the Shipit GitHub App/webhook installed (i.e., the attacker's own low-privilege repo — no access to the victim stack needed), and (2) a target commit SHA shared between the attacker's repo and the victim stack. SHA reuse across repositories is realistic in common workflows (forks, mirrored release branches, vendored/copied commits, monorepo extraction) and SHAs are public information readily discoverable via the GitHub UI/API. No `ApiClient` token, session, or write access to the victim repository is required — only a signed webhook from an app installation the attacker legitimately controls.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the payload's own repository, mirroring `PushHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
or otherwise join `Commit` through the repository resolved from `payload.dig('repository', 'full_name')` before applying any status update, so that a webhook authenticated for repository X can never mutate commit state belonging to repository Y.

### Proof of Concept
1. Attacker creates/controls Repository A and installs the same GitHub App used by the target Shipit instance (or otherwise obtains a validly signed "status" event for Repository A).
2. Attacker identifies a commit SHA `S` that is also tracked as part of Stack B (victim), e.g. because Stack B's tracked branch includes a commit that was cherry-picked/mirrored verbatim into Repository A, or a public open-source commit shared between both repos.
3. Attacker triggers (or crafts, since they own Repository A's webhook secret) a `status` webhook payload:
   ```json
   { "sha": "S", "state": "success", "context": "ci/required", "repository": { "full_name": "attacker/repo-a", "owner": { "login": "attacker" } } }
   ```
   signed with Repository A's legitimate webhook secret.
4. `WebhooksController#verify_signature` succeeds (signature matches for organization "attacker").
5. `StatusHandler#process` executes `Commit.where(sha: "S")`, which also matches the commit in Stack B, and calls `create_status_from_github!`, marking a required/blocking CI check as passing on Stack B's commit — potentially unlocking deploy/merge on Stack B despite the attacker having no access to it.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
