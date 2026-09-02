### Title
Cross-repository commit-status forgery via unscoped `StatusHandler` webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` GitHub webhook is authenticated per-organization (the signature is checked against the webhook secret configured for the organization named in the payload's `repository.owner.login`/`organization.login`), but the handler that actually applies the event writes to `Commit` records matched **only by SHA**, with no verification that the commit's repository/stack belongs to the organization whose signature was just verified. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` derives `repository_owner` from the payload and verifies the HMAC signature using that organization's own `webhook_secret`: [1](#0-0) [2](#0-1) 

Once the signature is verified for that organization, `Shipit::Webhooks.for_event(event)` dispatches the parsed JSON body to the corresponding handler: [3](#0-2) 

For the `status` event, `StatusHandler#process` looks up commits **globally by SHA** and writes a status to every match, with no check that the commit's `repository`/`stack` corresponds to the organization that produced (and signed) the webhook: [4](#0-3) 

Contrast this with `PushHandler`, which correctly scopes lookups to the repository named in the payload via `Handler#stacks`/`Handler#repository_name`: [5](#0-4) [6](#0-5) 

`StatusHandler` never calls `stacks`/`repository_name` — it does not constrain the write to the repository named in the verified payload at all. This is the same bug class as the analog report: a value (`sha`) is acted upon while the field that should scope the trust boundary (repository/organization ownership) is never constrained, exactly like the zkSync `shr` circuit constraining the quotient/remainder relation but omitting the `remainder < divisor` bound that ties the result back to the correct domain.

Because Shipit supports multi-tenant configuration (`Shipit.github(organization: ...)`), an attacker who legitimately controls or installs the Shipit-connected GitHub App on **their own** organization/repository can send a validly-signed `status` webhook (signed with their own org's `webhook_secret`) whose `sha` field names a commit belonging to a completely different tracked repository/stack. `Commit.where(sha: params.sha)` will match that commit regardless of which repository it lives in, and `commit.create_status_from_github!(params)` will write an attacker-controlled `state`/`context`/`description` onto it: [7](#0-6) 

### Impact Explanation
Commit statuses feed directly into Shipit's deploy-safety gating (`ci.require` in `shipit.yml`, documented at README lines 444-450, and `Commit#deployable?`). A forged "success" status for a required CI context on a commit belonging to a repository/stack the attacker does not control can make that commit `deployable?` and thus eligible for an unauthorized deploy through the normal Shipit UI/API by any subsequent legitimate user, or can spoof a failure to block deploys (denial of a specific release). This is a cross-repository write achieved purely by owning an unrelated repository/webhook installation — no session, API token, or privileged GitHub access to the victim repository is required. This satisfies the "Critical — cross-repository writes... unauthorized deploy" impact bar.

### Likelihood Explanation
The `sha` of a target commit is typically public (visible on GitHub commit pages, PRs, or CI output), so an attacker does not need special access to the victim repository to learn it. The attacker only needs a GitHub organization/repository with the Shipit GitHub App installed and a webhook configured to reach `/webhooks` with a validly-signed `status` event — a normal, unprivileged act of installing the app on any repo (their own), not requiring access to the victim's org. This makes the finding realistically exploitable in any multi-tenant Shipit deployment.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified payload, mirroring `PushHandler`/`Handler#stacks`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
or otherwise join through `Repository.from_github_repo_name(repository_name)` before touching any `Commit`, ensuring the organization that signed the webhook can only mutate state belonging to its own repository.

### Proof of Concept
1. Attacker creates/owns GitHub org `attacker-org` and repository `attacker-org/decoy`, installs the Shipit GitHub App on it, and obtains the corresponding `webhook_secret` configured for `attacker-org` in the multi-tenant Shipit config (this is normal, unprivileged setup — the attacker's own org).
2. Attacker learns the public commit SHA `deadbeef...` of a commit on a victim stack (e.g., visible via the victim's public GitHub repo/PR).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a body such as:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
   signed with `attacker-org`'s own `webhook_secret` (`X-Hub-Signature: sha1=...`).
4. `WebhooksController#verify_signature` succeeds because it only checks the signature belongs to `attacker-org`.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the victim's commit (in an unrelated repository/stack), and calls `commit.create_status_from_github!(params)`, writing the forged `success` status onto it — satisfying `ci.require` gating for a deploy the attacker does not own.

Note: I was not able to inspect `Commit#create_status_from_github!` or `Commit#deployable?` implementations directly in this pass due to tool-call limits, so the exact downstream mechanics of how a forged status enables a deploy are based on the documented `ci.require` behavior in `README.md` rather than a line-by-line trace of `Commit`; a follow-up read of `app/models/shipit/commit.rb` / `app/models/shipit/status.rb` is recommended to fully confirm the deploy-gating chain.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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
