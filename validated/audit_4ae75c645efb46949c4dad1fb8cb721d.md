### Title
Cross-repository `Status` forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table and writes a `Status` for every match, without ever checking that the webhook's `repository.full_name` (or `branches`) corresponds to the commit's own stack/repository. Any GitHub user who owns a repository with Shipit's webhook installed can call GitHub's public Statuses API on their own repo with a `sha` copied from a victim's public commit, and Shipit will write a forged `Status` for the victim's commit.

### Finding Description
The broken binding: `payload.dig('repository', 'full_name')` (the webhook's origin repo) must equal `commit.stack.repository.full_name` (the repo owning the matched commit) before a status coming from that webhook is applied to `commit`. This equality is never checked.

Code path:
- `Shipit::WebhooksController#create` dispatches the raw parsed payload directly to handlers with no repository scoping: [1](#0-0) 
- `verify_signature` only validates that the payload's signature matches the secret configured for `repository_owner` (`payload.dig('repository','owner','login')`) — it proves the webhook genuinely came from GitHub for *that* organization/repo, but says nothing about which commit sha it is allowed to reference: [2](#0-1) 
- `StatusHandler` declares a `branches` param (mirroring GitHub's real payload) but never reads it, and more importantly never reads `repository_name`/`stacks` (inherited from `Handler`) at all: [3](#0-2) 
- `Handler` exposes `repository_name`/`stacks` helpers precisely for this kind of scoping, but `StatusHandler` is the only status-related handler that ignores them: [4](#0-3) 
- `Commit.where(sha: params.sha)` is a global, unscoped query over every stack/repository in the Shipit instance: [5](#0-4) 

Exploit flow: an attacker who has push/admin access to their own GitHub repo (with Shipit's GitHub App/webhook installed on that org — a legitimate, unprivileged configuration) calls GitHub's real `POST /repos/:owner/:repo/statuses/:sha` API with an arbitrary `sha` string — GitHub's Statuses API does not require that sha to correspond to a real commit in that repo — set to a victim's public commit sha, `state: "success"` (or any state), and optional forged `context`/`description`/`target_url`. GitHub delivers this as a correctly-signed `status` webhook to Shipit (correct signature because it is genuinely for the attacker's own organization). `verify_signature` passes. `StatusHandler#process` then matches the victim's `Commit` row purely by `sha` and calls `commit.create_status_from_github!(params)`, writing a `Status` scoped to the *victim's* real stack (`stack_id` comes from the matched `Commit`, not from the webhook's repository).

Existing guards do not stop this: `verify_signature` authenticates the sender's own organization, not the target of the sha reference; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema only validates payload shape (types), not cross-object relationships; there is no `require_permission!`/`stacks`-scope check inside `StatusHandler` at all.

### Impact Explanation
An attacker who owns any repository configured with Shipit can forge a `Status` (success, failure, or any custom `context`/`description`/`target_url`) against an arbitrary victim commit in a completely unrelated stack, as long as they know or can guess the victim commit's sha (trivially available if the victim repo is public, or via commit messages/PRs). Since `Status` participates in deployability checks (`Commit#deployable?`, `blocking_statuses`, `required_statuses`, and the continuous-delivery scheduling in `Commit#schedule_continuous_delivery`), this can flip a victim commit from blocked/pending to "successful," enabling an unauthorized deploy, or forge a false failing/blocking status to sabotage a victim's release — this is a payload from one repository mutating another's stack/commit data, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "unauthorized deploy"). This is repeatable against any victim commit sha, for any repository on the same Shipit instance, at will.

### Likelihood Explanation
Preconditions: attacker needs a GitHub repository (their own, with any permission level over it — repo creation is free) with Shipit's webhook/GitHub App configured for their organization (a normal, low-privilege prerequisite for using Shipit at all), and knowledge of a victim commit sha (public for public repos). No Shipit session, API token, or secret is required. Cost is a single GitHub API call (`POST .../statuses/:sha`), fully repeatable and scriptable.

### Recommendation
In `StatusHandler#process`, restrict the update to commits whose stack belongs to the webhook's own repository, e.g. only update commits within `stacks` (the `Handler#stacks` helper already resolves `Repository.from_github_repo_name(repository_name)`):
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status payload from repository A cannot create a Status for a commit belonging to repository B" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

  attacker_repo_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'forged-ci',
    'repository' => { 'full_name' => 'attacker-org/unrelated-repo' },
    'branches' => [{ 'name' => 'nonexistent-branch' }],
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  end
end
```
With the current implementation this assertion fails (a `Status` is created for `victim_commit` even though `repository.full_name` never matches the victim stack's repo and `branches` names a non-existent branch), demonstrating the unscoped cross-repository write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
