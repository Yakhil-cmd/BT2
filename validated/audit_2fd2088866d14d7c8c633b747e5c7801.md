### Title
Webhook signature verification is bound to `repository.owner.login` while event processing is bound to `repository.full_name`, allowing cross-organization webhook forgery in multi-app deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
This is a structural analog of the reported bug class: a value the code trusts as "the verified identity" (`msg.sender` in the original report, here `repository.owner.login`) diverges from the value actually used to perform the sensitive operation (`_sender`/reward target in the report, here `repository.full_name` used to select the `Stack`/`Repository` acted upon). Shipit supports multiple GitHub Apps, one per organization, each with its own `webhook_secret` (`docs/setup.md` "Using Multiple Github Applications"). The signature check picks the secret to verify against using `repository.owner.login`, but the actual handler that mutates state picks the target repository using `repository.full_name` from the very same untrusted JSON body. Nothing forces these two fields to refer to the same organization.

### Finding Description
`WebhooksController#verify_signature` selects which `GithubApp` (and thus which `webhook_secret`) to use for HMAC verification based on a field read straight out of the unauthenticated JSON payload: [1](#0-0) [2](#0-1) 

Once the signature check passes, `WebhooksController#create` dispatches the same raw params to the registered handler: [3](#0-2) 

All handlers resolve which `Stack`/`Repository` to mutate using a *different* field of the same payload — `repository.full_name` — via the shared `Handler` base class: [4](#0-3) 

`PushHandler` triggers `stack.sync_github` for whatever stacks match that `full_name`/branch, and `StatusHandler` writes a CI status onto commits looked up only by `sha` (with no repository/organization scoping at all): [5](#0-4) [6](#0-5) 

Because `repository.owner.login` (used for signature/org selection) and `repository.full_name` (used for the actual write) are independent, unrelated keys inside the same attacker-controlled JSON body, an operator of one configured GitHub App/organization (`OrgOne`) — who legitimately knows `OrgOne`'s `webhook_secret` because they administer that org's app installation — can craft a payload where:
- `repository.owner.login = "OrgOne"` (or `organization.login`, the fallback used by `repository_owner`) so the HMAC verifies successfully with `OrgOne`'s known secret.
- `repository.full_name = "OrgTwo/victim-repo"` so the handler resolves and mutates a completely different organization's `Stack`.

This is exactly the report's bug class — the code authenticates one identity (`repository_owner` → app/secret) but performs the write using a different, unauthenticated identity (`repository.full_name` → target stack) — analogous to `_unstakeNFTs` authenticating via `msg.sender`/router but crediting rewards using an inconsistent target address.

### Impact Explanation
This breaks the binding "the organization that authenticated versus the repository that is written," explicitly called out in the analog rules. With `StatusHandler`, an attacker who controls one org's webhook secret can inject fabricated commit statuses (`state`, `context`, `target_url`) for *any* commit SHA across *any* stack tracked by the Shipit instance, since `Commit.where(sha:)` has no organization/repository scoping at all. Since Shipit's merge queue and deploy safety checks rely on GitHub commit statuses/CI requirements (`ci.require` in `shipit.yml`) to gate whether a deploy or merge may proceed, forging a "success" status on a victim repository's commit can unlock an unauthorized deploy — meeting the "unauthorized deploy" criterion for High/Critical impact. `PushHandler` similarly lets the attacker trigger `sync_github` (and downstream jobs) on a victim stack it does not own.

### Likelihood Explanation
Exploitation requires the attacker to be a legitimate administrator of *one* GitHub App installation configured in the same multi-tenant Shipit instance (per `docs/setup.md`'s documented "Using Multiple Github Applications" setup) — i.e., they hold no privileged Shipit session, `ApiClient` token, or victim-org credentials, only their own org's webhook secret, which they are entitled to know. This matches "unprivileged attacker" for the target organization while still being able to forge events for a sibling organization on the same instance.

### Recommendation
After verifying the HMAC signature, re-derive the app/organization used for verification and cross-check it against the `repository.full_name` (and any `repository.owner.login`) actually referenced by the handler before allowing any state mutation — i.e., ensure the `Repository`/`Stack` resolved for processing belongs to the same organization/app whose secret validated the signature. Concretely, pass the verified `organization` (or the resolved `GithubApp`) into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization: repository_owner) }` and have `Handler#stacks` reject any repository whose owner does not match `verified_organization`.

### Proof of Concept
1. Deploy Shipit with two configured GitHub Apps, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-app config), both apps installed and tracking stacks in the same Shipit instance.
2. Attacker administers `OrgOne`'s GitHub App and therefore knows `OrgOne`'s `webhook_secret`.
3. Attacker crafts a `status` (or `push`) webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" },
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(OrgOne_webhook_secret, body)>` and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgOne")` and verifies successfully using `OrgOne`'s secret.
6. `StatusHandler#process` (or `PushHandler#process`) resolves the target using `repository.full_name = "OrgTwo/victim-repo"` and writes a forged commit status / triggers a sync for `OrgTwo`'s stack, despite the attacker never having proven any relationship to `OrgTwo`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
