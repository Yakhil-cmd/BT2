### Title
Webhook signature verified against attacker-chosen organization while the handler acts on an unrelated `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's webhook secret to validate the HMAC against using an attacker-controlled field from the request body (`repository.owner.login` or `organization.login`), while the actual webhook `Handler` subclasses (e.g. `PushHandler`) act on a *different* field of the same body — `repository.full_name` — to decide which `Stack`/`Repository` to mutate. Nothing binds the two fields together, so a signature that is valid for organization A can be replayed to drive actions against a repository belonging to organization B.

### Finding Description
`WebhooksController` picks the signing organization from attacker-supplied JSON before any cryptographic check occurs: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a `GitHubApp` instance configured for whatever organization name the request body claims to be from (Shipit explicitly supports multiple orgs, each with its own `webhook_secret`, per `config/secrets.development.shopify.yml`). `verify_webhook_signature` then HMACs the raw body against *that* organization's secret: [3](#0-2) 

Once the signature check passes, `create` dispatches the full JSON body to all registered handlers, unmodified: [4](#0-3) 

But the handlers never re-check `repository.owner.login`. `Handler#repository_name` (used by every handler, including `PushHandler`) reads `repository.full_name` instead: [5](#0-4) [6](#0-5) 

So the field the signature verification keys off (`repository.owner.login`) and the field the handler actually acts on (`repository.full_name`) are two independent, attacker-controlled strings in the same payload. This is the same class of bug as the reported `approve()` issue: the value that is cryptographically bound/checked (allowance amount / signing organization) is not the value that ends up being consumed (transferred amount / target repository).

### Impact Explanation
An attacker who legitimately controls (or has been granted) a GitHub organization/App onboarded onto this Shipit instance — i.e. they know that organization's real `webhook_secret` — can forge a webhook whose `repository.owner.login`/`organization.login` names their own org (so signature verification succeeds against their own secret) while `repository.full_name` names a *different* organization's repository that also has a `Stack` configured in the same Shipit deployment. The forged, validly-"signed" request will then be processed by `PushHandler` (and other handlers keyed on `repository_name`) against the victim organization's stack, calling `stack.sync_github(expected_head_sha: params.after)` with attacker-chosen `after`/`ref` values, out of band from any real event on the victim's repository. This crosses a repository trust boundary the signature was supposed to enforce, without the attacker ever needing write access to, or credentials for, the victim's organization or repository — matching the "organization that authenticated versus the repository that is written" analog called out in scope.

### Likelihood Explanation
Any multi-tenant Shipit deployment (explicitly supported, as shown by the multi-org `config/secrets.*.yml` examples) that onboards more than one GitHub organization is exposed. The only prerequisite is that the attacker legitimately controls one onboarded organization's webhook secret (e.g., their own org/app in the same install) — no compromise of the victim org, no privileged Shipit session, and no `ApiClient` token is required. This is a straightforward, deterministic request-crafting exploit, not a race condition or edge case.

### Recommendation
Bind the field used to select/verify the webhook secret to the field the handlers act on:
- After signature verification succeeds for organization X, require that `repository.full_name`'s owner segment (and/or `organization.login`) matches X before processing, or
- Derive the signing organization strictly from the `Repository` record already known to Shipit for `repository.full_name` (looking up which org/app owns that repo) rather than from a raw payload field, and reject if the two disagree.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `attacker-org` (attacker knows its `webhook_secret`) and `victim-org` (has a `Stack` for `victim-org/prod-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-repo"
  },
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
3. Set `X-Hub-Signature: sha1=<hmac-sha1(body, attacker-org's webhook_secret)>`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the HMAC check passes because it was computed with the correct (attacker-known) secret. [1](#0-0) 
5. `create` calls `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`, and `PushHandler` resolves `stacks` via `repository.full_name = "victim-org/prod-repo"`, triggering `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim stack — an action the attacker has no legitimate authority to trigger. [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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
