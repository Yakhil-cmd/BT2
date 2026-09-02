This confirms the mechanism. In multi-org mode, `Shipit.github(organization: repository_owner)` (`lib/shipit.rb:170-181`) picks a distinct `GitHubApp` per organization, each with its own independently configured `webhook_secret` (`lib/shipit/github_app.rb:44-51`). If that org's secret is unset, `verify_webhook_signature` unconditionally returns `true` (`lib/shipit/github_app.rb:76-77`). Crucially, the signature-verification org lookup and the object actually mutated are derived from **two different JSON fields of the same attacker-controlled, not-yet-verified raw body**:

- `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) to select which app/secret verifies the signature — `app/controllers/shipit/webhooks_controller.rb:59-62`.
- `Handler#repository_name` (used by every webhook handler, e.g. `PushHandler`) reads `payload.dig('repository', 'full_name')` to select the `Repository`/`Stack` that gets acted on — `app/models/shipit/webhooks/handlers/handler.rb:36-38`.

Since GitHub never actually sends a payload where `repository.owner.login` and `repository.full_name` disagree, this split trust is invisible under normal operation — but nothing in the code enforces that the two fields are consistent within the raw POST body.

### Title
Webhook signature verification org does not match repository acted upon, allowing cross-organization stack forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/secret to validate `X-Hub-Signature` against using `repository.owner.login` (or `organization.login`) from the unauthenticated raw body, while every `Handler` subclass (`PushHandler`, etc.) resolves the target `Repository`/`Stack` using the independent `repository.full_name` field from that same body. In a multi-organization Shipit deployment (`Shipit.github(organization:)`, `lib/shipit.rb:170-181`), an attacker can craft a payload whose `repository.owner.login` names an organization configured with a blank/nil `webhook_secret` (which is optional per `config/secrets.development.example.yml:11`), while `repository.full_name` names a repository belonging to a *different*, properly-secured organization.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)   # from repository.owner.login
verified = github_app.verify_webhook_signature(sig, raw_post)
``` [1](#0-0) 

`GitHubApp#verify_webhook_signature` treats an unconfigured secret as "always verified":
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [2](#0-1) 

Once verification passes, `WebhooksController#create` dispatches to handlers using the full, attacker-controlled `params`:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [3](#0-2) 

Every handler locates the target stack from a *different* field than the one used for signature verification:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler#process` then triggers `stack.sync_github(expected_head_sha: params.after)` for whatever stack matches `repository.full_name`: [5](#0-4) 

The binding that should hold is: **organization whose signature was verified == organization owning the repository the handler mutates**. This is broken because the two are read from independently-attacker-settable JSON keys in the same unauthenticated request body, and the equality is never asserted in code.

### Impact Explanation
An attacker who knows (a) a configured organization in the multi-org Shipit setup that has no `webhook_secret` set (a supported, documented configuration — see `config/secrets.development.example.yml`), and (b) the `full_name` of a real, actively-deployed stack under a *different*, secured organization, can POST a forged `push`/`status`/`check_suite` payload with mismatched `repository.owner.login` vs `repository.full_name`. This passes signature verification trivially (secret-less org) yet drives `GithubSyncJob`/status/check-run handlers to act on the victim organization's stack — e.g., forcing `stack.sync_github` to pull and append attacker-chosen "expected head sha" commits, or forging commit `status`/`check_suite` results that `continuous_deployment` gating relies on to trigger automatic deploys. This can lead to an unauthorized deploy being triggered on a stack the attacker never had credentials for, matching the "unauthorized deploy" High/Critical impact category.

### Likelihood Explanation
Requires no credentials, no session, and no GitHub App private key — only knowledge of the target's multi-org configuration (which organizations have `webhook_secret` unset) and the target repository's `owner/name`, both of which are often publicly discoverable (e.g., via the Shipit UI, which lists stacks by `owner/name`). Any Shipit instance configured with multiple GitHub orgs where at least one lacks a webhook secret is exposed; the code path requires zero additional attacker capability beyond POSTing to the public `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, assert that the organization used to select the verifying `GitHubApp` is the same organization embedded in `repository.full_name` (i.e., derive both from the same field, or explicitly compare `repository_owner` against `repository.full_name.split('/').first` and reject on mismatch before dispatching to handlers). Additionally, consider disallowing an unset `webhook_secret` from silently granting "verified" status in multi-org configurations, or require explicit opt-in for that behavior.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `AttackerOrg` (no `webhook_secret`) and `VictimOrg` (has `webhook_secret`, owns stack `VictimOrg/prod-app`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "VictimOrg/prod-app",
    "owner": { "login": "AttackerOrg" }
  }
}
```
No valid `X-Hub-Signature` is required since `AttackerOrg` has no `webhook_secret` → `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`).
3. `WebhooksController#create` dispatches this payload to `PushHandler`, which resolves `Repository.from_github_repo_name("VictimOrg/prod-app")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, causing `GithubSyncJob` to run against the victim's stack — potentially triggering deploy status checks/continuous deployment for a repository the attacker was never authorized to touch.

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
