### Title
Cross-organization webhook forgery breaks the "authenticating org == acted-upon repository" binding, enabling forged CI status/push events on repositories in other organizations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a webhook against based on `repository_owner`, a value read straight out of the untrusted, attacker-supplied JSON body. But the handlers that actually act on the payload (e.g. `PushHandler`, `StatusHandler`) resolve the target `Stack`/`Commit` using a *different* field from the same body: `repository.full_name`. Because the HMAC signature only proves the payload was signed with *some* configured organization's secret — not that the organization used for verification matches the organization whose repository is mutated — an attacker who legitimately controls one organization onboarded to a shared Shipit instance can forge webhook deliveries that are "verified" under their own org's secret while acting on a completely different organization's stacks.

### Finding Description
`verify_signature` picks the `GithubApp` used to validate the signature via: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

where `repository_owner` is: [2](#0-1) 

`params.dig('repository', 'owner', 'login')` — a field taken directly from the JSON body the controller itself is about to trust.

Once `verify_signature` passes, `create` dispatches the *entire same raw body* to event handlers: [3](#0-2) 

Handlers, however, resolve the affected `Stack`/`Repository`/`Commit` using a **different** field of the payload — `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` uses this to sync arbitrary stacks: [5](#0-4) . `StatusHandler` uses `params.sha` (not repository-scoped at all) to look up commits and record a fabricated CI status: [6](#0-5) .

Shipit supports multiple organizations configured simultaneously, each with its own `webhook_secret`, exactly the multi-tenant configuration shown in the repo's own sample config: [7](#0-6) .

**The broken binding, stated as an equality that should hold but doesn't:**
`organization whose webhook_secret authenticated the request` == `organization whose repository/commit the handler mutates`.

An attacker who is an unprivileged (relative to the victim org) but legitimate administrator of *their own* org "orgA" (also configured in the same shared Shipit instance) knows `orgA`'s `webhook_secret`. They can POST directly to `/webhooks` (nothing enforces the sender must be GitHub's IP range or that the request went through GitHub) with:
- `repository.owner.login = "orgA"` (used only for HMAC-secret selection — passes verification),
- `repository.full_name = "orgB/victim-repo"` and/or a `sha` belonging to a commit in `orgB`'s stack (used by the handler to select what gets mutated).

They then compute a valid `X-Hub-Signature` themselves using the `orgA` secret they legitimately possess, producing a request that is "verified" yet mutates `orgB`'s data.

### Impact Explanation
This crosses an authentication/repository-ownership boundary analogous to the audited bug's "unchecked return equated with success" pattern: the code treats "signature verified against org X's secret" as equivalent to "payload's repository claims are trustworthy for org X," when they are not bound together. Concretely reachable impacts:
- `StatusHandler` lets the attacker fabricate a `success` CI status on an arbitrary commit SHA of a victim stack they don't own, which (via `Status#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery`) can trigger an **unauthorized deploy** on continuous-deployment-enabled stacks belonging to another organization: [8](#0-7)  and [9](#0-8) .
- `PushHandler` can trigger `GithubSyncJob` against arbitrary victim stacks.
- `CheckSuiteHandler`/`MembershipHandler` similarly act on payload-declared identifiers without organization pinning.

This satisfies the Critical bucket ("an unauthorized deploy") defined in the task's impact list.

### Likelihood Explanation
Requires a Shipit deployment shared across multiple GitHub organizations/GitHub Apps (explicitly a supported/documented configuration), and requires the attacker to control one of those onboarded orgs' webhook secret — a credential they legitimately hold for their own tenant, not for the victim's. No session, `ApiClient` token, or GitHub write access to the victim repo is needed; only knowledge of one's own org's `webhook_secret`, which is by design available to org admins.

### Recommendation
Cross-check that `repository.owner.login` used to select the verifying `GithubApp`/secret is the *same* organization present in `repository.full_name` (and any other org-derived identifiers used downstream, e.g. commit lookups) before dispatching to handlers; reject the payload otherwise. Alternatively, scope the resolved secret to the exact repository (not just its owner) and have handlers assert that the organization implied by the fields they act on matches the organization whose secret validated the request.

### Proof of Concept
1. Attacker is an admin of GitHub org `orgA`, which is configured in Shipit's `secrets.yml` alongside victim org `orgB` (multi-org install), and thus knows `orgA`'s `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "sha": "<victim commit sha in orgB/victim-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and sends `POST /webhooks` with header `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and validates successfully using the attacker's own known secret.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — which belongs to `orgB`'s stack — and creates a fabricated `success` status, potentially triggering `ContinuousDeliveryJob` and an unauthorized deploy of `orgB/victim-repo`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
