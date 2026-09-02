### Title
Webhook Signature Verification Is Bound to the Wrong Payload Field, Allowing Cross-Organization Stack Sync/Deploy Triggering - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against using one untrusted field of the JSON body (`repository.owner.login`, falling back to `organization.login`), but the handler that actually decides *which* `Stack`/`Repository` to act on uses a completely different, unvalidated field of the same body (`repository.full_name`). Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "the repository that gets written to" are never proven to be the same repository. This is the direct structural analog of the reported bug class: an untrusted value (`ticket_count`) is used to drive processing without validating it against the data it's supposed to describe.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

and skips signature verification entirely for that organization if no `webhook_secret` has been configured for it: [3](#0-2) 

Per-organization configuration explicitly documents `webhook_secret` as optional: [4](#0-3) [5](#0-4) 

Meanwhile, the actual event routing/target-resolution logic ignores `repository_owner`/`organization.login` entirely and instead resolves the target `Repository`/`Stack` from `repository.full_name` — a sibling field in the same, potentially-unsigned JSON body: [6](#0-5) 

and the push handler then synchronizes/updates that stack with attacker-supplied `after` (target SHA): [7](#0-6) 

The binding that should hold is:
`organization authenticated by verify_signature (repository_owner)` == `organization owning the repository actually acted upon (repository.full_name)`

Because `repository_owner` and `repository.full_name` are independent, attacker-controlled fields of the same POST body, and because a Shipit installation can legitimately track multiple GitHub organizations (as shown by the multi-org secrets examples), an attacker only needs one tenant organization in the deployment to be configured without a `webhook_secret` (an explicitly supported/documented configuration) to defeat the check for the entire request, then freely set `repository.full_name` to point at any other tracked (victim) organization's repository.

### Impact Explanation
An unauthenticated attacker can craft an HTTP POST to `/webhooks` with `X-Github-Event: push`, setting `repository.owner.login` (or `organization.login`) to the unprotected tenant and `repository.full_name` to `victim-org/victim-repo`. This request sails through `verify_signature` (no secret means `verify_webhook_signature` returns `true`) and is then dispatched to `PushHandler`, which looks up stacks strictly by `repository.full_name` and calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack for the guessed branch. This lets an attacker force a resynchronization of a victim organization's stack state using attacker-chosen `after`/`ref` values they have no authorization over. On stacks with continuous deployment enabled, a forced sync can trigger an automatic deploy — an unauthorized deploy of a repository the attacker does not control, crossing the organization boundary that the signature check was supposed to enforce.

### Likelihood Explanation
Exploitation requires no credentials, no GitHub App key, and no session — only that the running Shipit instance manages at least one tenant organization without a configured `webhook_secret`, which the project's own setup documentation explicitly allows ("Webhook secret (optional)"). Any multi-tenant or lightly-configured deployment following the documented optional-secret path is exposed, and the request itself is a trivial unauthenticated HTTP POST.

### Recommendation
- Require `webhook_secret` for every configured GitHub organization (or globally refuse unsigned webhooks) rather than defaulting `verify_webhook_signature` to `true` when unset.
- Cross-validate that `repository.full_name`'s owner matches the same organization identity (`repository_owner`) that was used to select/verify the signing secret before routing to a handler.
- Avoid computing "who authenticated this request" and "what resource will be modified" from two independent, unauthenticated payload fields without an explicit equality check between them.

### Proof of Concept
Given a Shipit instance configured with two organizations, e.g.:
```yaml
github:
  attacker-org:
    app_id: 1
    installation_id: 1
    # webhook_secret not set (optional)
  victim-org:
    app_id: 2
    installation_id: 2
    webhook_secret: "s3cr3t"
```
An unauthenticated attacker sends:
```
POST /webhooks
X-Github-Event: push

{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-existing-on-github>"
}
```
`verify_signature` resolves `repository_owner` = `"attacker-org"`, finds no `webhook_secret` configured for it, and `verify_webhook_signature` short-circuits to `true` [8](#0-7) . The request then reaches `PushHandler#process`, which resolves the target purely from `repository.full_name` = `"victim-org/victim-repo"` [9](#0-8)  and calls `stack.sync_github(expected_head_sha: params.after)` on the victim stack [10](#0-9) , causing an unauthorized cross-organization sync (and potential auto-deploy) despite the request never being validated against `victim-org`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
