### Title
Signature verification keyed on `repository.owner.login` while repository lookup keyed on `repository.full_name` allows cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook's HMAC against using `repository_owner`, a value read straight out of the unauthenticated JSON body. Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the target `Repository`/`Stack` using a *different* field from that same body: `repository.full_name`. Because Shipit is designed to host multiple organizations, each with its own independent `webhook_secret` [1](#0-0) , "which secret authenticated this request" and "which repository/stack the request acts on" are two unrelated payload fields that are never cross-checked.

### Finding Description
`verify_signature` computes the authenticating organization from the payload, not from any transport-level identity: [2](#0-1) [3](#0-2) 

It calls `Shipit.github(organization: repository_owner)` and verifies the signature with that organization's `webhook_secret`. `GitHubApp#verify_webhook_signature` uses that secret's HMAC to check `X-Hub-Signature`: [4](#0-3) 

Once `verify_signature` passes, `create` dispatches the *entire raw payload* to the matching handlers, which never re-check `repository.owner.login`. Instead, the base `Handler` class (and every subclass that touches a stack) resolves the target repository purely from `repository.full_name`: [5](#0-4) 

For example, `PushHandler` acts on every non-archived stack of the resolved repository and forces a GitHub sync to an attacker-chosen `after` SHA: [6](#0-5) 

`PullRequest::ClosedHandler` (and its siblings `OpenedHandler`, `ReopenedHandler`, `LabeledHandler`, etc.) similarly resolve the repository from `params.repository.full_name` and mutate review stacks (archive/unarchive) accordingly: [7](#0-6) [8](#0-7) 

**Equality that is broken:** the engine implicitly assumes `organization-authenticating-the-signature == owner(repository-being-acted-on)`. In reality only `repository.owner.login == organization used to pick webhook_secret` is checked; `repository.full_name`'s owner is never compared against it. An attacker who legitimately controls a second, low-trust GitHub organization that is *also* configured on the same shared Shipit instance (a supported, documented multi-org deployment shape, see `secrets.development.shopify.yml` / `docs/setup.md`) can craft a payload where:
```json
"repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
```
and sign it with `attacker-org`'s own `webhook_secret` (which the attacker legitimately possesses, since it is the secret for the organization the attacker administers). `verify_signature` will authenticate the request using `attacker-org`'s key and accept it, while every handler will act on `victim-org/victim-repo`'s stacks. This is aggravated further because `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank/unset for the resolved organization [9](#0-8) , so if any onboarded organization in the shared config omits `webhook_secret` (a state the shipped config template explicitly allows, `webhook_secret: # nil`), an attacker needs no secret at all — merely knowledge of that organization's login name — to forge webhooks against any *other* organization's repositories on the same instance.

### Impact Explanation
This crosses a genuine credential-boundary: possession of organization A's webhook credential (or knowledge that organization A has no configured secret) grants the ability to forge write-triggering events for organization B's stacks. Concretely this allows an attacker who administers one onboarded, low-trust org to: force `sync_github` to an arbitrary commit SHA on a victim stack's tracked branch, archive/unarchive victim review stacks, and manipulate victim pull-request-driven state — all without ever holding a Shipit session, `ApiClient` token, or the victim organization's real webhook secret. This matches the "High" bar of unauthenticated write into stack/task state that should have required the victim organization's own webhook trust.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (an explicitly supported and documented configuration), and (2) the attacker controlling (or being a member/admin of) at least one of the onboarded organizations, or any onboarded organization having a blank `webhook_secret`. Given Shipit's documented multi-tenant usage pattern and that `webhook_secret` is presented as optional in the sample config, this is a realistic deployment condition rather than a purely theoretical one.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, enforce that the organization used to select the verifying secret is derived from (or matched against) the same trust-anchored value used for repository resolution — e.g., after verifying the signature for `repository_owner`, require `repository.full_name.split('/').first == repository_owner` before dispatching to handlers, and reject otherwise. Additionally, disallow the "no secret configured → auto-verified" fallback in `GitHubApp#verify_webhook_signature`, or make `webhook_secret` mandatory per organization, so an unconfigured secret cannot be leveraged to forge events for any repository.

### Proof of Concept
1. Configure two organizations on one Shipit instance: `attacker-org` (attacker-controlled, `webhook_secret: s3cr3t`) and `victim-org/victim-repo` (existing stack, unrelated secret).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` and sends `POST /webhooks` with `X-Github-Event: push` and the resulting `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, verifies successfully against `attacker-org`'s secret [2](#0-1) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` via `repository_name` = `payload.dig('repository','full_name')` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stacks [6](#0-5) , all without ever authenticating against `victim-org`'s own webhook secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
