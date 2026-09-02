### Title
StatusHandler creates commit statuses globally by SHA, breaking the organization-that-authenticated vs. repository-that-is-written binding, enabling cross-repository status forgery and unauthorized continuous deployment - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub `status` webhook against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`) field. [1](#0-0)  However, once the signature check passes, `StatusHandler#process` never re-checks that the commit it updates actually belongs to that same organization/repository: it looks up commits by `sha` alone, across the entire Shipit instance. [2](#0-1) 

This breaks the required binding: `organization that authenticated == repository that is written`. An attacker who administers any organization/repository configured in the same Shipit instance (and therefore legitimately knows that org's `webhook_secret`) can forge a `status` webhook whose signature is valid for their own org, but whose `sha`/`state`/`context` target a commit that belongs to a completely different tracked repository/stack.

### Finding Description
The webhook signature verification step resolves the GitHub App/secret to use purely from the attacker-controlled JSON body:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`Shipit.github(organization: repository_owner)` is used to fetch the corresponding `GitHubApp` (and hence its `webhook_secret`) to verify the signature: [4](#0-3) . This confirms the request was signed with the secret of *some* organization tracked by the app — but says nothing about which repository/stack the payload's other fields (like `sha`) actually affect.

Once verified, `WebhooksController#create` dispatches the parsed payload to `StatusHandler.call`: [5](#0-4) 

`StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Unlike other handlers (`PushHandler`, `PullRequest::*Handler`), `StatusHandler` does **not** inherit the base `Handler#repository_name`/`stacks` scoping by repository full name [6](#0-5)  — it queries `Commit` globally by `sha`, which is not unique across the whole database (only unique per `stack_id`, per the `index_commits_on_stack_id_and_sha` migration). Any two stacks (belonging to different organizations/repositories tracked by the same Shipit instance) that happen to share a commit SHA — trivially achievable since SHAs are public/content-addressable and can be replicated into any git repository the attacker controls, e.g. by fetching/cherry-picking a public commit from the victim repository into their own — will both have their `Status` records updated by a single forged webhook.

Creating a status is not inert: `Commit#create_status_from_github!` → `Commit#add_status` emits hooks and, critically, calls `stack.schedule_merges` for `success`/`pending` states, and `Status#schedule_continuous_delivery` triggers continuous delivery logic. [7](#0-6) [8](#0-7)  If the victim stack has `continuous_deployment` enabled, injecting a fabricated `success` status for a commit SHA can cause an unauthorized deploy of that stack, entirely orchestrated by an attacker who never had credentials for the victim's organization — only for their own, unrelated one.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out in scope: the webhook signature check authenticates one organization, but the actual database write (and its side effects — CI status propagation, continuous delivery scheduling) is not confined to that organization's repositories/stacks. Depending on stack configuration this can escalate to an unauthorized deploy, which is listed as a Critical impact category.

### Likelihood Explanation
The attacker needs no privileged access to the victim's repository or Shipit session — only administrative control (webhook configuration) over *any* organization/repository already registered with this Shipit instance, which is a much weaker bar than the "no credential, repository, execution boundary crossed" exclusion, since here the org boundary is exactly what's crossed. Obtaining a colliding SHA is feasible for public repositories or forks/mirrors, and the vulnerable code path (`Commit.where(sha: params.sha)`, unscoped) is directly reachable via the documented `status` webhook event.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the repository identified in the payload (as the base `Handler#stacks`/`repository_name` does for other handlers), e.g. restrict the `Commit.where(sha: ...)` lookup to `stacks` derived from `payload.dig('repository', 'full_name')`, and additionally verify that the `repository_owner` used for signature verification is consistent with `repository.full_name`'s owner before dispatching to any handler.

### Proof of Concept
1. Attacker administers `attacker-org/attacker-repo`, a repository/organization registered in the same Shipit instance, and therefore knows (or can rotate) its GitHub App `webhook_secret`.
2. Attacker fetches or cherry-picks a public commit `SHA_X` from the victim's tracked repository `victim-org/victim-repo` into `attacker-org/attacker-repo` (SHAs are content-addressable and identical across repos).
3. Attacker crafts a `status` event payload: `{"sha": "SHA_X", "state": "success", "context": "ci/forged", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"}}` and signs it with `attacker-org`'s known `webhook_secret`, sending it to `WebhooksController#create`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully validates the HMAC. [4](#0-3) 
5. `StatusHandler#process` runs `Commit.where(sha: "SHA_X")`, which matches the commit record belonging to `victim-org/victim-repo`'s stack (because SHAs are globally, not per-org, matched), and creates a `success` status on it. [2](#0-1) 
6. If the victim stack has continuous deployment enabled, this triggers an unauthorized deploy via `Status#schedule_continuous_delivery`. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
