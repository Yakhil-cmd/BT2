### Title
Webhook signature verified against one organization while the acted-upon repository is taken from an unverified field of the same payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the unverified JSON body, before the signature has been checked. Once verification passes, the webhook body is handed unmodified to handlers (e.g. `PushHandler`) which resolve the `Repository`/`Stack` to act on using a *different* field of that same untrusted payload: `repository.full_name`. Shipit explicitly supports multiple GitHub Apps/orgs, each with its own `webhook_secret` (`docs/setup.md`, `config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`). This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 

where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`repository_owner` is read straight from the raw, unauthenticated request body and is only used to *select the secret*, never to constrain what the payload can subsequently claim. After `verified` is true, `create` dispatches the full, untouched payload to handlers:
```ruby
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [3](#0-2) 

Handlers then resolve the target `Repository`/`Stack` from a **different, independent** field of the same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

and act on it, e.g. `PushHandler#process` enqueues a sync of any matching stack:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

Shipit's own documentation and test fixtures confirm multiple, independently-secreted GitHub Apps/orgs are a supported configuration:
```yaml
# github:
#   somegithuborg:
#     webhook_secret: # nil
#   someothergithuborg:
#     webhook_secret: # nil
``` [6](#0-5) 
and `Shipit.github(organization:)` is looked up per-org with `GithubOrganizationUnknown` raised only if the org itself is not configured at all, not if the two payload fields disagree. [7](#0-6) 

Because `repository.owner.login` (used to pick the signing key) and `repository.full_name` (used to pick the acted-upon repository) are two independent, attacker-controlled strings in the same JSON body, and the signature only covers the raw bytes (proving the sender knows *some* configured org's secret, not that the two fields agree), an actor who administers/controls any org configured in Shipit (i.e., knows that org's own `webhook_secret`, which they set themselves when creating their GitHub App) can forge a signature that verifies successfully for their own org while making `repository.full_name` point at a stack belonging to an entirely different, victim-owned repository also connected to the same Shipit instance. This is the direct analog of the CLPool bug: a value used to satisfy one check (`repository_owner` / verified signature) is not the value subsequently acted upon (`repository.full_name` / staked liquidity tick), letting a party with a valid credential for one binding invoke effects on an unrelated binding.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" boundary explicitly called out as Critical impact. A party who legitimately controls one GitHub organization/app registered in a multi-org Shipit deployment can forge webhook events (e.g. `push`, `status`, `check_suite`) that Shipit will treat as authentic for a *different* organization's repository/stack, triggering `sync_github`, commit status creation, or CI check-run refresh against that victim stack. Depending on continuous-deployment settings, a forged/legitimate-looking `push`/`status` update for a victim stack can trigger unwanted deploys via Shipit's continuous delivery pipeline.

### Likelihood Explanation
Requires the Shipit instance to be configured with more than one GitHub App/org (a documented, supported configuration), and the attacker must control at least one of those configured orgs (their own `webhook_secret`, which they define). No access to the victim org's secret, session, or API token is needed — only knowledge of one's own org's secret and the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint with crafted JSON. This is a plausible, unprivileged-attacker scenario in shared/multi-tenant Shipit deployments.

### Recommendation
Cryptographically or structurally bind the field used to select the verifying secret to the field(s) subsequently acted upon: e.g., after signature verification, re-derive/re-validate that `repository.full_name`'s owner matches the same `repository_owner`/org whose secret validated the signature (or reject payloads where `repository.owner.login` and the owner segment of `repository.full_name` diverge) before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two orgs, `org-attacker` (attacker-controlled GitHub App, attacker knows `webhook_secret_A`) and `org-victim` (has a Stack `org-victim/victim-repo`), per the documented multi-org `secrets.yml` layout.
2. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_A, raw_body)` using their own known secret.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and the signature verifies successfully (attacker used their own secret correctly).
6. `PushHandler#process` is invoked with the full payload; `repository_name` resolves to `"org-victim/victim-repo"` via `payload.dig('repository','full_name')`, matching the victim's `Repository`, and `stack.sync_github(expected_head_sha: ...)` is triggered on the victim stack — despite the signature only proving control of `org-attacker`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
```
