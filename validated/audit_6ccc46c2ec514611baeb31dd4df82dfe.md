### Title
Webhook signature verification is bound to an attacker-controlled `repository.owner.login` field while the executed action is bound to a different, unverified `repository.full_name` field, allowing forged GitHub events for any stack whose owning organization has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to validate the request against using `repository_owner`, a value read straight out of the unverified JSON body [1](#0-0) [2](#0-1) . The handlers that actually execute side effects (sync a stack, create a commit status, archive a review stack, etc.) instead resolve the target repository/stack from a *different* payload field, `repository.full_name` [3](#0-2) [4](#0-3) . Because the signature check "authenticates" the organization named in `repository.owner.login` while the write happens against the repository named in `repository.full_name`, and `verify_webhook_signature` trivially returns `true` whenever the selected organization has no `webhook_secret` configured, an attacker can pick any org in the deployment's config that lacks a secret, put it in `repository.owner.login`, and set `repository.full_name`/`branch`/`sha` to point at a stack belonging to a fully-secured organization.

### Finding Description
`verify_signature` computes:
```
github_app = Shipit.github(organization: repository_owner)   # from payload, unverified
verified = github_app.verify_webhook_signature(header_sig, raw_post)
``` [1](#0-0) 

`GithubApp#verify_webhook_signature` is a no-op when the selected app has no configured secret:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [5](#0-4) 

Once verification "passes" (or organization lookup succeeds for an org with a blank `webhook_secret`), `WebhooksController#create` dispatches the entire raw payload to every registered handler for the event [6](#0-5) . Handlers never re-check `repository.owner.login`; they resolve the target stack purely from `repository.full_name`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler`, for example, then triggers a github sync for every matching stack/branch based on that unrelated field:
```
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

This breaks the intended binding: `repository.owner.login` (the field the signature "authenticates") must equal `repository.full_name`'s owner (the repository actually written to). The engine enforces neither equality nor any correlation between the two fields, and both are attacker-supplied in the exact same unauthenticated HTTP POST that is being validated.

### Impact Explanation
An unauthenticated network attacker who knows (or guesses) that at least one configured GitHub organization in `Shipit.github_configs` has no `webhook_secret` set - a state the app itself documents as normal/expected (`webhook_secret: # nil` in the sample config) [7](#0-6)  - can forge `X-Github-Event` requests naming that org in `repository.owner.login` while pointing `repository.full_name` at any stack belonging to a properly secured organization. This lets the attacker:
- Force `GithubSyncJob`/`sync_github` on arbitrary stacks via forged `push` events.
- Inject fabricated commit `Status` records via `StatusHandler`, which can flip a commit's CI/deployability state and unlock continuous-deployment/auto-deploy gates (`Commit#deployable?`, `Stack#deployable?`) without any real CI signal.
- Drive `pull_request`/`membership` handlers, including team/membership mutation, an explicit High-impact category (escalation into `Shipit.github_teams` authorization).

This satisfies the rule's "organization that authenticated versus the repository that is written" binding-break category and can lead to unauthorized deploy triggering/state manipulation, matching the report's underlying bug class (a check performed against the wrong/unbound identity allows the attacker to force a privileged outcome), just as the original report's `voteRecord` was checked but never bound to the correct voter/proposal pair.

### Likelihood Explanation
Exploitation requires no credentials, no Shipit session, and no GitHub App secret - only knowledge that some organization configured on the instance has no `webhook_secret` (common in development/staging setups, and discoverable by trial since the response differs between "unknown organization" (422 + specific log) and "verified" outcomes). The attacker only needs to reach the public `/webhooks` endpoint, which is unauthenticated by design.

### Recommendation
Bind the signature-verifying identity to the identity actually acted upon: require that the organization derived from `repository.full_name` (the value handlers use) matches the organization used to select the webhook secret in `verify_signature`, and reject the request if they differ. Additionally, do not treat a missing `webhook_secret` as an implicit "verified" bypass in production configurations - require an explicit secret for every configured organization, or fail closed when a webhook claims an organization with no secret but the payload references a repository under a different, secured organization.

### Proof of Concept
1. Configure `config/secrets.yml` with two organizations, e.g. `victim-org` (has `webhook_secret: real-secret`) and `throwaway-org` (no `webhook_secret`, or entirely absent from config with the organization present in another already-recognized way).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "throwaway-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required since `Shipit.github(organization: "throwaway-org").verify_webhook_signature` returns `true` (no secret configured) per `lib/shipit/github_app.rb:76-83`.
3. `WebhooksController#create` dispatches this payload to `PushHandler`, which resolves `victim-org/victim-repo`'s stacks via `repository.full_name` and calls `stack.sync_github(expected_head_sha: ...)`, executing an action against the victim organization's stack despite the signature check having been satisfied only for the unrelated `throwaway-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L6-14)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
