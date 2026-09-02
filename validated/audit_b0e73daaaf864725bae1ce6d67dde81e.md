### Title
Webhook signature verified against `repository.owner.login` while handlers act on the independent `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-org Shipit deployments (`config/secrets.yml` with `github: { org_a: {...webhook_secret...}, org_b: {...webhook_secret...} }`), `WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC verification based solely on `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` [1](#0-0) . That check only proves the request was signed with the secret belonging to whatever organization is named in `repository.owner.login`. It does not verify or constrain the separate `repository.full_name` field that the actual event handlers use to select which `Repository`/`Stack` to act on [2](#0-1) [3](#0-2) .

### Finding Description
`Shipit.github(organization:)` resolves a distinct `GitHubApp` (and its own `webhook_secret`) per organization key in `secrets.github` [4](#0-3) . `verify_signature` picks that organization strictly from the JSON body's `repository.owner.login` (or `organization.login`) field:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

Once the signature validates for that organization, `create` hands the entire raw JSON `params` to every registered handler for the event, unmodified and un-scoped [5](#0-4) . Handlers such as `Handler#repository_name` and `PushHandler#process` derive the target repository from a *different* JSON field, `repository.full_name`, and use it to look up `Repository.from_github_repo_name` and enqueue a sync against the matched `Stack`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 
```
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

`repository.owner.login` and `repository.full_name` are independent, attacker-controlled JSON fields inside the same unsigned-at-the-field-level payload — the HMAC only covers the raw byte string as a whole, but nothing in the application logic enforces that the organization used to select the verifying secret is the same organization embedded in `full_name`. An operator/attacker who controls (or has compromised) a GitHub App installation for **any one** organization configured in `secrets.github` — e.g. their own low-privilege org `attacker-org` — knows or can obtain that org's `webhook_secret` (webhook secrets are configured per-org specifically to let each org's own admins manage their integration) and can compute a valid HMAC-SHA1 signature over an arbitrary JSON body. They can set `repository.owner.login = "attacker-org"` (so `verify_signature` authenticates against the `attacker-org` secret) while setting `repository.full_name = "victim-org/victim-repo"` (a repository belonging to a different, unrelated organization also configured in the same Shipit instance). This breaks the binding: **organization that authenticated (`repository.owner.login` → `attacker-org`'s secret) ≠ repository that is written (`repository.full_name` → `victim-org/victim-repo`)**.

The impact depends on the handler: for `push`, this forges a `GithubSyncJob` for the victim's stack with an attacker-chosen `expected_head_sha`, which drives what commit Shipit believes is at the head of the branch and can be resynced/deployed from [6](#0-5) ; for `pull_request`/`status`/`check_suite` handlers the same `repository.full_name`-based lookup pattern is repeated [7](#0-6) .

### Impact Explanation
This crosses the "unauthorized deploy/rollback" boundary: an attacker who administers a low-trust org's GitHub App installation (and therefore its `webhook_secret`) inside a shared, multi-tenant Shipit instance can forge events attributed to a completely different, victim organization's repository, triggering sync/deploy-adjacent state changes (`sync_github`) on stacks they were never authorized to touch. This matches the report's core bug class — a verification check that authenticates one identity/scope while the downstream trust decision silently acts on a different, unverified identity/scope drawn from the same request.

### Likelihood Explanation
Requires the target Shipit instance to be configured with multiple GitHub organizations in `secrets.github` (the multi-org / `github_app_config` code path exists specifically for this) and requires the attacker to control (or have compromised) the webhook secret of at least one configured, lower-privileged organization. This is a realistic scenario for shared/multi-tenant Shipit deployments (the exact use case the multi-org config supports), but does not apply to the common single-org Shipit setup where `github_default_organization` is nil and there's only one secret to verify against [8](#0-7) .

### Recommendation
In `WebhooksController#verify_signature`, after selecting the GitHub App by `repository_owner`, additionally assert that `repository_owner` matches the owner segment parsed out of `repository.full_name` (and reject/`head(422)` on mismatch) before dispatching to handlers, so the organization whose secret validated the signature is provably the same organization whose repository the handlers subsequently act on.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `attacker-org` (attacker knows/controls its `webhook_secret`) and `victim-org` (has a real `Stack` tracking `victim-org/victim-repo`).
2. Craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature [9](#0-8) , then `PushHandler` looks up `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `sync_github(expected_head_sha: "<attacker-chosen sha>")` against the victim's stack [6](#0-5)  — despite the signature never having been verified with `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** lib/shipit.rb (L183-188)
```ruby
  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```
