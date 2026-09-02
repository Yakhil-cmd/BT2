### Title
Webhook signature check binds to `repository.owner.login`/`organization.login` while every event handler trusts the unbound `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using a field read out of the same untrusted JSON body it is about to validate (`repository.owner.login`, falling back to `organization.login`). Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the target `Stack`/`Repository` using a *different* field from that body: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, and duplicated in every `pull_request/*_handler.rb`). There is no check that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login`. This is the same class of bug as the reported `getOwedFee` issue: a value that is authenticated (the organization identity used to pick the secret) is not the same value that is subsequently acted upon (the repository whose stack gets mutated).

### Finding Description
- `verify_signature` computes `repository_owner` from the raw, unauthenticated payload and uses it only to pick *which* configured `webhook_secret` should validate the signature: [1](#0-0) [2](#0-1) 
- Each organization configured in `Shipit.github` has its own independent `webhook_secret`, `app_id`, and `private_key`: [3](#0-2) 
- The signature check only proves the request body was HMAC-signed with *that organization's own secret* - it says nothing about which repository the body claims to be for: [4](#0-3) 
- Once the signature passes, every handler (`PushHandler`, `StatusHandler`, all `PullRequest::*Handler`) looks up the `Stack`/`Repository` via `repository.full_name`, a field that was never cross-checked against `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding that should hold:** `organization whose secret validated the signature == organization prefix of repository.full_name acted upon`.
**Binding that actually holds:** these are two independently attacker-controlled fields inside the same JSON body; only their existence is required, not their relationship to each other.

In a multi-tenant Shipit installation (multiple orgs configured under `Shipit.github`, as the sample secrets file demonstrates), a party who legitimately controls one configured GitHub App/organization (and therefore genuinely knows *that org's* `webhook_secret`, since they created/installed the app) can freely construct any JSON body - including a `repository.full_name` pointing at a completely different organization's stack - and sign that body correctly with their own secret. `verify_signature` only asks "does this signature match the secret for `repository.owner.login`?" - if the attacker sets `repository.owner.login` to their own org, the check passes trivially, yet `repository.full_name` used by the handler can name any repository already registered as a `Stack` in Shipit, regardless of the org that supposedly emitted the event.

### Impact Explanation
This lets an attacker who legitimately controls one tenant's GitHub App configuration forge `push`, `status`, and `pull_request` events for a `Stack` belonging to an unrelated tenant/organization in the same Shipit instance:
- Forged `push` events cause `PushHandler` to invoke `stack.sync_github(expected_head_sha:)` on a victim's stack, resyncing commits from GitHub for a repository the attacker doesn't control.
- Forged `status` events create fabricated CI/commit statuses on a victim's tracked commits (`StatusHandler#process` → `Commit#create_status_from_github!`), which feed directly into `Stack#next_commit_to_deploy`/CI gating logic used by `ContinuousDeliveryJob#perform` to decide whether to `trigger_continuous_delivery`. Faking a green CI status on a victim stack that has continuous deployment enabled can cause an unauthorized automatic deploy of a commit that never actually passed CI.
- Forged `pull_request` events can create/archive/unarchive review stacks for a victim's repository via `PullRequest::OpenedHandler`/`ReopenedHandler`/`ClosedHandler`.

This crosses the "unauthorized deploy" / "cross-repository writes" impact bar defined in scope, since it lets one tenant/organization inject events that mutate another tenant's stack state and CI signal without ever proving ownership of that repository.

### Likelihood Explanation
Requires only that the attacker be a legitimate operator of *some* GitHub organization/App already configured in the same Shipit deployment (i.e., they know their own `webhook_secret` because they created it) - no compromise of the victim's credentials, no `ApiClient` token, and no repository write access to the victim repo is needed. This matches a realistic scenario for any Shipit instance shared across multiple organizations/teams, which the codebase explicitly supports (`config/secrets.*.yml` show multiple orgs configured side by side).

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), after verifying the HMAC, additionally verify that the organization/login that owns the verified secret matches the owner segment of `repository.full_name` (and of `organization.login` for org-scoped events) before dispatching to any handler. Reject the webhook (422) if these do not match, e.g.:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) and return unless verified

  # New: bind the authenticated org to the repository actually referenced by the payload
  repo_full_name = params.dig('repository', 'full_name')
  if repo_full_name && repo_full_name.split('/').first&.casecmp?(repository_owner) == false
    head(422)
    return
  end
  ...
end
```

### Proof of Concept
1. Shipit is configured with two tenants in `Shipit.github`: `org-evil` (attacker-controlled GitHub App, attacker knows its `webhook_secret`) and `org-victim` (has a `Stack` for `org-victim/app` with continuous deployment enabled).
2. Attacker crafts a `push` (or `status`) webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to Shipit, or existing commit sha>",
  "repository": { "owner": { "login": "org-evil" }, "full_name": "org-victim/app" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_of_org-evil, body)` themselves (`lib/shipit/github_app.rb:76-83`), since they legitimately possess `org-evil`'s secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-evil")` and the signature validates successfully.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-victim/app")` and calls `sync_github` on the victim's stack - or, for a forged `status` event, `StatusHandler#process` creates a fabricated passing CI status on a victim commit, which `ContinuousDeliveryJob` can then use to auto-deploy that commit on `org-victim/app`.

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
