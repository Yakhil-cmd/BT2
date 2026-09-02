### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in StatusHandler - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `sha` across the entire database and mutates their status, without checking that the commit's owning `Repository`/`Stack` matches the GitHub organization whose `webhook_secret` was used to verify the request signature. Any org with a configured `GithubApp` can therefore forge a `status` webhook that mutates commit status state for a `sha` belonging to a completely different, unrelated repository/stack.

### Finding Description
Broken binding: `Shipit.github(organization: repository_owner_of_signing_org).verify_webhook_signature(...)` verifying == `commit.stack.repository.owner` for every `Commit` whose `state`/status gets mutated. These are NOT the same in this handler.

Path:
1. `WebhooksController#create` dispatches the raw JSON payload to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` succeeds. `verify_signature` only resolves `Shipit.github(organization: repository_owner)` using `params.dig('repository', 'owner', 'login')` from the attacker-controlled payload and checks the signature against that org's `webhook_secret`. [1](#0-0) [2](#0-1) 

2. Because `repository_owner` is read straight from the same attacker-supplied `payload`, an attacker who legitimately owns/administers `attacker-org` (and thus can obtain a correctly-signed request using `attacker-org`'s real `webhook_secret`, e.g. by triggering a real webhook from their own repo, or by computing the HMAC themselves if they control the org's app config) can set `payload['repository']['owner']['login'] = 'attacker-org'` while setting `payload['sha']` to any commit sha they want to target, even one that exists only in an unrelated stack/repository.

3. `StatusHandler`'s parameter schema only requires `sha` and `state` — it never requires or reads `repository` for scoping purposes: [3](#0-2) 

4. `process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup across every stack in the Shipit instance. The base `Handler` class does provide a `stacks` helper scoped by `payload.dig('repository', 'full_name')`, but `StatusHandler` does not use it at all: [4](#0-3) [5](#0-4) 

5. `Commit#create_status_from_github!` unconditionally creates a `Status` record and can trigger `deployable_status`/`commit_status` hooks and schedule merges (`stack.schedule_merges`) for that victim commit/stack: [6](#0-5) [7](#0-6) 

Existing guards checked and found insufficient:
- `verify_signature` only authenticates that the *body* was signed by *some* org's secret; it never re-checks that the org matches the commit's actual owning repository at the point of mutation.
- `drop_unhandled_event` and `ExplicitParameters` schema only validate presence/type of `sha`/`state`, not ownership.
- No `require_permission!`/`User#authorized?` check exists in this path since webhooks are inherently unauthenticated-by-session and rely purely on signature-to-owner binding, which this handler breaks.

### Impact Explanation
An attacker who controls (or can trigger legitimate webhook delivery from) any GitHub organization/app registered in `Shipit.github_apps` can flip the CI status of commits belonging to any other tenant's stack in the same Shipit instance, as long as they can guess or discover the victim commit's `sha` (git SHAs are often publicly visible via GitHub, PR pages, CI logs, etc.). This can mark a victim's commit as `success`, causing it to become `deployable?` and potentially triggering an actual deploy/merge (`stack.schedule_merges`) — this is a payload for one repository mutating another's commit/stack state, matching the "Critical" impact category (cross-repository mutation / unauthorized deploy trigger).

### Likelihood Explanation
Preconditions: attacker needs a `GithubApp`/`webhook_secret` for at least one org configured in `Shipit.github_apps` (they can be a legitimate, unprivileged owner of their own small org/repo integrated with the same Shipit instance) and knowledge of a target commit `sha` in another stack. Both are realistic for a multi-tenant Shipit deployment shared across many orgs/teams — sha values are not secrets. The attack requires no Shipit session, API token, or elevated GitHub permissions, and is repeatable against any known sha.

### Recommendation
In `StatusHandler`, require `repository.full_name` (and/or `repository.owner.login`) in the params schema, and scope the commit lookup through the `stacks` helper already provided by `Handler` (e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent), matching the pattern used by other handlers like `PullRequest::LabeledHandler`, so only commits belonging to the repository named in the verified payload are mutated.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (or a new StatusHandler test):
```ruby
test ":status webhook signed for one org mutates a commit belonging to a different stack/org" do
  # attacker_org signs the request legitimately with its own webhook_secret
  victim_commit = shipit_commits(:cyclimse_first) # belongs to a different stack/org than "shipit"
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  request.headers['X-Github-Event'] = 'status'
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: forged_payload, as: :json
  end

  assert_equal 'success', victim_commit.reload.state
end
```
Both sides of the binding diverge: the verified signing organization is `attacker-org` (from `payload['repository']['owner']['login']`), while the mutated record's owning organization is whatever org owns `shipit_commits(:cyclimse_first)`'s stack — they are not equal, yet the mutation still succeeds because `StatusHandler#process` never checks `payload['repository']` against the commit's actual stack/repository.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
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
