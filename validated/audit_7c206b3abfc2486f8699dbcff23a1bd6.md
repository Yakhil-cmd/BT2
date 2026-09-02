### Title
Cross-Repository Commit Status Forgery via Unscoped `sha` Lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The external report's root cause — a unique identifier (`vault name`) that is not permanently bound to the entity it originally identified, allowing a party who controls that identifier value to act on/impersonate a different owner's resource — has a structural analog in Shipit's GitHub `status` webhook handling. `WebhooksController#verify_signature` authenticates a webhook by matching the payload's `repository.owner.login` (or `organization.login`) to a per-organization `webhook_secret` [1](#0-0) , but the actual write performed by `StatusHandler#process` is resolved purely by commit `sha` with no scoping back to the authenticated repository/organization [2](#0-1) .

### Finding Description
`WebhooksController` verifies that an incoming webhook was signed with the secret belonging to the organization named in `repository.owner.login` of the payload: [1](#0-0) 

This establishes the binding: *"organization authenticated" == organization whose secret signed the request*.

However, `StatusHandler#process` never uses `repository` at all to scope the write. It looks up `Commit` rows by `sha` alone, across the entire `commits` table (i.e. across every `Stack`/`Repository` Shipit tracks), and applies the incoming status to whatever commit matches: [2](#0-1) 

Compare this to `Handler#stacks`, the base helper other handlers (e.g. `PushHandler`) correctly use to scope work to the repository named in the payload: [3](#0-2) [4](#0-3) 

`StatusHandler` bypasses this scoping mechanism entirely. The binding that should hold is: *"organization/repository authenticated by the webhook signature" == "repository whose commit's status is written"*. Because `StatusHandler` keys only on `sha` (a value that is public and can be identical across repositories — forks, mirrors, or repositories sharing history/rebased branches), an actor who can get GitHub to send a legitimately-signed `status` event for their own repository (i.e., any repository/organization onboarded onto Shipit with the App installed) can supply a `sha` that matches a commit belonging to a completely different, victim `Stack`/`Repository` tracked by the same Shipit instance. Shipit will then create a `Status` on that victim commit via `Commit#create_status_from_github!`, even though the authenticated signer never owned that repository.

### Impact Explanation
Commit statuses in Shipit gate deploy safety and merge-queue decisions (`release_status?`, `supports_fetch_deployed_revision?` and related checks delegate through `cached_deploy_spec`/status context checks on `Stack`) [5](#0-4) . An attacker who controls (or has the ability to trigger events from) any one onboarded repository can inject/forge a status on an unrelated victim stack's commit, without ever needing the victim organization's webhook secret, an `ApiClient` token, or a Shipit session. This is a cross-repository write and satisfies the "unauthorized deploy/rollback" impact category, since forged "success" statuses can unblock safety checks gating deploys on a repository the attacker doesn't own.

### Likelihood Explanation
Exploitation requires only that the attacker's own onboarded repository (or organization) has GitHub's App installed with a valid webhook secret — i.e., no privileged Shipit credential is needed, only ordinary control over some repository event that produces a `status` webhook (e.g., a CI integration reporting a status on a commit whose `sha` the attacker chooses/knows, since git shas are public). Discovering a victim's commit sha is trivial (public commit history via GitHub UI/API). No signature forgery is required — the attacker relies on their own legitimately-signed webhook while the target write bypasses repository scoping.

### Recommendation
Modify `StatusHandler#process` to scope the `Commit` lookup to the repository identified in the verified payload (mirroring `Handler#stacks`), e.g. resolve commits only within `stacks` (which are already scoped to `Repository.from_github_repo_name(repository_name)`), rather than querying `Commit.where(sha: params.sha)` globally:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently join through `stacks` when querying commits, ensuring the authenticated organization/repository binding from `WebhooksController#verify_signature` is enforced for every write the handler performs.

### Proof of Concept
1. Onboard/attacker-control `Repository` A (`attacker-org/attacker-repo`) on the same Shipit instance, with the GitHub App properly installed (legitimate, unprivileged access — no Shipit session/token needed).
2. Identify a commit sha `S` belonging to a victim `Stack` tracked under `victim-org/victim-repo` (commit shas are public).
3. Trigger (or directly send, if the attacker has any status-reporting integration on repo A) a GitHub `status` webhook event for repository A containing `{"sha": "S", "state": "success", ...}`. GitHub signs this with repo A's org webhook secret; `WebhooksController#verify_signature` passes because it only checks that the *signer* (org A) is legitimate.
4. `Shipit::Webhooks.for_event('status')` invokes `StatusHandler`, which executes `Commit.where(sha: "S")` — matching the victim's commit row regardless of which repository it belongs to — and calls `create_status_from_github!`, writing an attacker-controlled status onto the victim's commit/stack.

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

**File:** app/models/shipit/stack.rb (L107-117)
```ruby
    delegate(
      :provisioning_handler_name,
      :find_task_definition,
      :release_status?,
      :release_status_context,
      :release_status_delay,
      :supports_fetch_deployed_revision?,
      :supports_rollback?,
      to: :cached_deploy_spec,
      allow_nil: true
    )
```
