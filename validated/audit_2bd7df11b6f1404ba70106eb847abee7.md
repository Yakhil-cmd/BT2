### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while repository writes are resolved from unbound `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by looking up the GitHub App config for the organization named in `repository.owner.login` (or `organization.login`) and validating the HMAC over the raw body against that organization's `webhook_secret`. Once the signature check passes, every webhook `Handler` resolves the target `Repository`/`Stack` using a **different** field in the same payload — `repository.full_name` — which is never cross-checked against the organization that was actually authenticated.

### Finding Description
`verify_signature` picks the signing secret using only the repository owner/organization login: [1](#0-0) [2](#0-1) 

`Shipit::Webhooks::Handlers::Handler#repository_name` — used by every concrete handler (`PushHandler`, `StatusHandler`, pull-request handlers, etc.) to locate the `Repository`/`Stack` to act on — instead reads `repository.full_name`: [3](#0-2) 

Because the HMAC signature only proves "this exact JSON body was signed with secret S", and S is looked up from `repository.owner.login`, an attacker who legitimately controls a GitHub organization/app installation on Shipit (and therefore knows their own `webhook_secret`) can post a crafted, self-signed payload directly to the `/github/webhooks` endpoint where:
- `repository.owner.login` == `organization.login` == attacker's own org (so signature verification succeeds with the attacker's known secret), and
- `repository.full_name` == an arbitrary victim `owner/repo` that Shipit tracks.

`PushHandler#process` then resolves stacks purely from `full_name` and acts on them: [4](#0-3) 

This breaks the intended binding `verified_organization == owner_of_repository_written`. The equality that should hold — `repository_owner (signed/verified) == repository.full_name owner (acted upon)` — is never enforced.

### Impact Explanation
This allows cross-repository writes: an attacker who only controls one organization's webhook configuration in Shipit (their own, low-privilege tenant) can forge webhooks that are treated as authentic for any other tracked repository. Via `PushHandler`, this can force `Stack#sync_github` with an attacker-chosen `expected_head_sha` on a victim's stack; via `StatusHandler`, it can inject arbitrary commit statuses (`context`, `state`, `target_url`) against a victim commit, which can be used to satisfy `required_statuses`/CI gating in `DeploySpec` and enable an unauthorized deploy. This matches the Critical impact bar for cross-repository writes / unauthorized deploy.

### Likelihood Explanation
Medium-High: it requires the attacker to control one legitimate (even unprivileged) GitHub App/organization installation known to Shipit — no repository write access, Shipit session, or `ApiClient` token is required, only knowledge of their own org's webhook secret and the ability to send a raw HTTP POST to the public webhook endpoint. `repository.full_name` is entirely attacker-supplied JSON, not otherwise validated against the signing organization.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the repository being acted upon belongs to the same organization whose secret verified the signature — e.g., derive/validate `repository.full_name`'s owner against `repository_owner`/`organization.login` before dispatching to handlers, and reject the webhook (422) on mismatch.

### Proof of Concept
1. Attacker owns/administers GitHub org `attacker-org`, which is configured in Shipit with `webhook_secret = S` (their own tenant configuration).
2. Attacker crafts a `push` payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` themselves (they know `S`) and POSTs directly to Shipit's `/github/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the HMAC using `S`. [1](#0-0) 
5. `PushHandler` resolves stacks from `victim-org/victim-repo` (via `repository_name`) and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — a write triggered by a webhook that was never authenticated on behalf of `victim-org`. [3](#0-2) [4](#0-3)

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
