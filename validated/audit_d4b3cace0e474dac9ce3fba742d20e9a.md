### Title
Webhook signature verification keys on `repository.owner.login`, but event processing acts on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to verify the HMAC signature against using `repository_owner`, which is read straight out of the unauthenticated JSON body (`params.dig('repository', 'owner', 'login')`). Once verification "passes," the same raw body is dispatched to event handlers, which resolve the target `Stack`/`Repository` from a *different* field of the same body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so the org whose secret was used to authenticate the request is not the repository that ends up being mutated.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
`verify_signature` picks the `GitHubApp` config via `Shipit.github(organization: repository_owner)` and `repository_owner` is derived from the request body itself: [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations configured independently, each with its own (optional) `webhook_secret`, as shown in the shipped example configs: [4](#0-3) 
and in the multi-org test fixture where `OrgTwo` also has `webhook_secret: # nil`: [5](#0-4) 
`docs/setup.md` itself calls the webhook secret "optional":
`Webhook secret (optional): Fill it with some randomly generated string...`

Once `verify_signature` passes (i.e., the request body claims to come from whichever org string maps to a config with `webhook_secret` unset, or one the attacker can forge), the `create` action dispatches the **same** raw payload to handlers: [6](#0-5) 

Handlers resolve the affected `Repository`/`Stack` using an independent field, `repository.full_name`, with no cross-check against `repository.owner.login` used for signature selection: [7](#0-6) 

The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login) == organization/repository actually written by the handler (repository.full_name)`

This binding is never enforced. Both values are attacker-supplied fields inside the same unauthenticated JSON body, and the code only validates the signature against the org named in one of them.

### Impact Explanation
Once an attacker finds/knows an org configured in `Shipit.github` with no `webhook_secret` (a state the engine explicitly supports and treats as "always verified"), they can submit a webhook body where:
- `repository.owner.login` (and/or `organization.login`) = the no-secret org, satisfying `verify_signature`.
- `repository.full_name` = any other repository/stack actually tracked by this Shipit instance.

This lets an unauthenticated actor drive any registered webhook handler against an arbitrary tracked stack, e.g.:
- `push`: force `stack.sync_github(expected_head_sha: params.after)` to an attacker-chosen sha for any stack. [8](#0-7) 
- `status`: inject fabricated commit statuses (`create_status_from_github!`) for any commit sha, which feeds directly into deploy/merge-queue CI gating logic (`ci.require`/`merge.require` checks). [9](#0-8) 

Fabricated/forced statuses can clear CI-required gates used by `MergeRequest#reject_unless_mergeable!` and the merge queue, which can lead to an unauthorized merge/deploy path being unlocked. This satisfies the "unauthorized deploy/rollback/merge" High/Critical impact bar in scope.

### Likelihood Explanation
Exploitation requires only that one org configured on the Shipit instance has `webhook_secret` unset — a state the engine's own docs and shipped sample configs describe as normal/optional, not a documented misconfiguration to be excluded. No GitHub credentials, session, or API token are needed; the request is a plain unauthenticated POST to `/webhooks` with a crafted JSON body and matching (or absent-secret) signature header. Any Shipit instance that manages multiple GitHub orgs and leaves one without a webhook secret (e.g., an internal/staging org) is exposed to cross-organization forgery against all other tracked repositories.

### Recommendation
Bind the value used for signature verification to the value used for repository resolution: require `repository.full_name`'s owner to equal the `repository_owner` used to select the `GitHubApp`/secret, and reject the payload otherwise. Additionally, do not treat a missing `webhook_secret` as automatic verification success when a request claims an unrelated target repository; consider requiring every org that owns a tracked repository to have a non-blank `webhook_secret`, or at minimum verify the resolved `Repository`'s configured owner against the payload's `repository.owner.login` prior to dispatch.

### Proof of Concept
1. Configure Shipit with two orgs: `NoSecretOrg` (no `webhook_secret`) and `VictimOrg/some-repo` (tracked stack, secret configured).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "NoSecretOrg" },
    "full_name": "VictimOrg/some-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "NoSecretOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `PushHandler` resolves the target stack via `Repository.from_github_repo_name("VictimOrg/some-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")`, acting on `VictimOrg`'s stack despite the request never being authenticated for `VictimOrg`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
