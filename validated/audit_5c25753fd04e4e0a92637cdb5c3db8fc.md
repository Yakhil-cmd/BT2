### Title
Cross-tenant CI status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `sha` across the entire `commits` table and writes a GitHub status to every match, without verifying that the commit's owning stack/repository corresponds to the organization whose webhook secret authenticated the request. Any org with a valid `webhook_secret` can forge a `status` event naming a foreign commit `sha` (discoverable via public GitHub history) and write a status onto another tenant's commit.

### Finding Description
The broken binding is: `commit.stack.repository` (the repository owning the `Commit` row mutated by `process`) must equal `repository_owner`/the repository authenticated in `verify_signature` for the incoming payload. This equality is never checked.

Path:
- `Shipit::WebhooksController#verify_signature` derives `repository_owner` purely from the payload's own `repository.owner.login` (or `organization.login`) field [1](#0-0) , and validates the signature using `Shipit.github(organization: repository_owner)`'s secret [2](#0-1) . This only proves the request was signed by org-x's secret for a repository org-x itself named in the payload — it proves nothing about which commit/stack the payload's `sha` will affect.
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no `stack_id`/repository filter at all [3](#0-2) .
- `Commit#create_status_from_github!` unconditionally creates a `Status` and triggers `add_status`, which updates `status`, emits `commit_status`/`deployable_status` hooks, and can schedule merges — all scoped to whatever stack the matched commit belongs to [4](#0-3) [5](#0-4) .

Attacker flow: org-x owns a legitimate Shipit-connected repo and has `webhook_secret`. They discover, via public GitHub, a commit SHA that belongs to org-y's stack. They send `POST /webhooks` with `X-Github-Event: status`, `repository.owner.login: org-x`, signed with org-x's secret, and `sha` set to org-y's commit, `state: success`. `verify_signature` passes (org-x's own secret verifies a payload org-x itself crafted). `process` finds the `Commit` row by global `sha` match — which belongs to org-y's stack — and writes a forged `success` status to it, potentially flipping `deployable?` and triggering continuous deployment (`schedule_continuous_delivery`) for org-y's stack.

No existing guard prevents this: `verify_signature` only checks signature validity against a repository name supplied by the attacker themselves, not against the commit being mutated; `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not ownership; there is no `stack_id`/`repository` scoping in the `Commit.where` query.

### Impact Explanation
An attacker controlling any onboarded org/repository (with its own `webhook_secret`) can write arbitrary CI status entries (`success`/`failure`/`pending`, with custom `context`, `description`, `target_url`) onto any other tenant's commit, as long as they can learn that commit's SHA (trivially available for any public GitHub repo). This can flip `Commit#deployable?` to true, unblocking or falsely triggering `stack.schedule_continuous_delivery`, i.e. causing an unauthorized/incorrect deploy decision on org-y's stack — a payload for one repository mutating another's commit/stack state. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions are modest: the attacker needs their own onboarded org with a working `webhook_secret` (a normal, low-privilege state for any Shipit-connected org), and knowledge of a target commit SHA (public information for public repos on GitHub). No Shipit session, API token, or victim's secret is required. The request is a single unauthenticated-to-Shipit-session HTTP POST, fully repeatable against any known SHA.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and other handlers using global `sha`/branch lookups) by the repository that was actually authenticated in `verify_signature`, e.g. join through `stack.repository` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_owner: ..., repository_name: ... })`, matching against `params.dig('repository', 'full_name')` rather than trusting a global SHA match across all tenants.

### Proof of Concept
```ruby
test "status webhook does not write status to a commit from a different repository/org" do
  org_x_stack = shipit_stacks(:shipit) # belongs to org-x, has webhook_secret
  org_y_stack = create_stack(repository_owner: 'org-y', repository_name: 'private-repo')
  victim_commit = org_y_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => org_x_stack.repository_owner }, 'full_name' => org_x_stack.repository_full_name }
  }

  assert_difference -> { victim_commit.statuses.count }, 0 do
    Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)
  end
end
```
Assert `victim_commit.reload.statuses.count == 0` (i.e., the org-y commit's binding `commit.stack.repository == repository authenticated for the request` holds) after calling the handler with a payload only validly signed for org-x; currently this assertion fails because the handler writes the status regardless of repository ownership.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
