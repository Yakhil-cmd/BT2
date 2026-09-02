### Title
Cross-organization webhook forgery: `repository.owner.login` used for signature-key selection does not bind to `repository.full_name` used for stack resolution - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a signature against based on `repository.owner.login` (or `organization.login`), both attacker-supplied JSON fields, while the downstream webhook handlers resolve the target `Repository`/`Stack` using the independent, also attacker-supplied `repository.full_name` field. Because the HMAC signature only proves "this body was signed with organization X's webhook secret" and never binds `owner.login` to `full_name`, any tenant that legitimately holds a webhook secret for their own GitHub organization on a shared Shipit instance can forge a signed webhook body that names their own org as `repository.owner.login` (to pass signature verification) while setting `repository.full_name` to a victim organization's repository, causing Shipit to act on the victim's stack.

### Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the unauthenticated JSON body (`params.dig('repository', 'owner', 'login')`), and this value is used to select which org's `GitHubApp` (and thus which `webhook_secret`) is used to verify `X-Hub-Signature`: [1](#0-0) 

Once the signature check passes, `WebhooksController#create` dispatches the same raw JSON body to the registered handler(s): [3](#0-2) 

Handlers such as `PushHandler` resolve the actual `Repository`/`Stack` to operate on using a *different* JSON field, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) 

and `PushHandler#process` enqueues a GitHub sync for every non-archived stack under that repository, using attacker-controlled `ref`/`after` parameters to pick the branch and expected head SHA: [5](#0-4) 

There is no code path that checks `repository.owner.login == repository.full_name.split('/').first` (or equivalent) before acting. The HMAC signature is only a proof of "the sender knows organization X's `webhook_secret`" - it says nothing about which repository the payload describes, because `owner.login` (used to pick the verification key) and `full_name` (used to pick the target repo/stack) are two independent, unauthenticated fields inside the same signed blob. Any party who is a legitimate, low-privilege GitHub App installer/webhook holder for *their own* organization on a shared Shipit instance can therefore choose `owner.login` = their own org (so the correct secret is selected and the signature verifies) while setting `full_name` = a victim org/repo they have no access to, and Shipit will happily act on the victim's stack.

This is the same class of bug as the reported Trident issue: a check is performed on one representation of "how much value was received" (`amount1Desired`) while a different, unguarded computation is credited (`liquidity`), letting the attacker satisfy the check while acting on unrelated state. Here, the check is "is this signed by org X's secret" while the state acted upon is "which repository does `full_name` name" - two unbound values that should be, but are not, cryptographically tied together.

### Impact Explanation
This breaks the trust binding "the organization that authenticated" (via webhook secret) versus "the repository that is written" (resolved via `full_name`). Any tenant/organization with a legitimate Shipit App installation (and hence a valid webhook secret for their own org) can forge webhook deliveries that are attributed to and acted upon for a completely different organization's repositories/stacks that they were never granted access to. Concretely with `PushHandler`, this triggers `Repository#stacks` -> `Stack#sync_github(expected_head_sha:)` jobs against a victim's stack chosen entirely by the attacker via `repository.full_name`, `ref`, and `after` — i.e. cross-repository/cross-tenant interference triggered without any credential for the victim organization. This matches the in-scope "cross-repository writes" impact category, since it allows one org's credentials to cause GitHub-sync/state actions against another org's repository that the attacker was never authorized to touch.

### Likelihood Explanation
Likelihood is realistic only in deployments where the Shipit instance is configured to serve multiple GitHub organizations/tenants (i.e., `Shipit.github` config contains multiple orgs, each with its own `webhook_secret`, as documented/supported by `GitHubApp#initialize` and `Shipit.github(organization:)`). In such multi-tenant setups, any org admin who can configure a GitHub App/webhook for their own org (an otherwise unprivileged, expected capability) can exploit this without needing any credential belonging to the victim org. In single-tenant deployments (one org configured) this reduces to a self-attack with no impact, so the severity is tenant-count-dependent, but the vulnerable code path itself has no additional gating.

### Recommendation
Bind the signature-verifying organization to the repository actually being acted upon before dispatching to handlers: after `verify_signature` resolves `repository_owner`, require that the owner segment of `repository.full_name` (and/or `organization.login`) equals `repository_owner` exactly, and reject (422) otherwise. Alternatively, resolve the target `Repository`/`Stack` first by `full_name`, then verify the signature using the `webhook_secret` associated with that repository's actual owning organization (not an attacker-chosen field), so the two lookups can never diverge.

### Proof of Concept
1. Shipit is configured with at least two orgs: `attacker-org` (attacker holds/administers a Shipit GitHub App installation and thus knows its `webhook_secret`) and `victim-org` (has a stack tracking `victim-org/victim-repo`).
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s own `webhook_secret` over the raw body, and sends `POST /webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner` = `"attacker-org"` [2](#0-1) , loads `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully since the attacker signed with the correct (their own) secret.
5. `create` parses the same body and dispatches it to `PushHandler`, which resolves `repository_name` from `full_name` = `"victim-org/victim-repo"` [4](#0-3)  and enqueues `sync_github(expected_head_sha: "<attacker-chosen-sha>")` for every matching stack of the victim's repository [5](#0-4) , despite the request being authenticated only against `attacker-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
