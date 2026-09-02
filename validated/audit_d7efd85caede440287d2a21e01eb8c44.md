### Title
Webhook signature is verified against `repository.owner.login`, but the handler dispatch resolves the target Stack/Repository from the unauthenticated `repository.full_name` field, letting any tenant with a valid `webhook_secret` for their own GitHub organization forge synchronization events against a different organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature with based on `repository_owner`, taken from the payload field `repository.owner.login` (or the `organization.login` fallback). [1](#0-0) [2](#0-1)  Once the signature check passes, the same raw payload is dispatched to handlers, but every handler resolves the actual `Repository`/`Stack` it acts on from a *different* field: `payload.dig('repository', 'full_name')`. [3](#0-2)  Nothing ties these two fields together, so the organization whose secret authenticated the request is not guaranteed to be the organization whose repository is actually written to.

### Finding Description
Shipit supports multi-tenant configuration where multiple GitHub organizations each have their own `webhook_secret`, as shown in the sample secrets file with `somegithuborg` and `someothergithuborg` each configured independently. [4](#0-3) 

The single `/github/webhooks` endpoint accepts a raw JSON body and:
1. Reads `repository.owner.login` from the body to select which org's `webhook_secret` to use for signature verification: [1](#0-0) 
2. If verification with that secret succeeds, dispatches the **entire raw payload** to all registered handlers for the event: [5](#0-4) 
3. Handlers such as `PushHandler` and the base `Handler#stacks` resolve the target `Repository` using `payload.dig('repository', 'full_name')`, an entirely separate field from the one used for signature selection: [6](#0-5) [7](#0-6) 

Since the attacker fully controls the raw HTTP body they send, they can set `repository.owner.login` to their own organization (for which they legitimately hold/installed a GitHub App and therefore know the `webhook_secret`) while setting `repository.full_name` to `victim-org/victim-repo`, a stack tracked under a different, unrelated organization on the same Shipit instance. Because the HMAC is only used to authenticate "this request came from someone who knows organization X's secret" and X is picked from a payload field independent of the field the handler trusts to select the write target, the equality `organization_authenticated == repository_written` does not hold. The attacker never needs to compromise the victim org's webhook secret, GitHub App, or Shipit session — they only need their own legitimately-configured org's secret.

### Impact Explanation
This breaks a deployment-trust binding at the "organization that authenticated versus the repository that is written" boundary called out in scope. The `push` handler's `stack.sync_github(expected_head_sha: params.after)` call is driven by the attacker-supplied `after` SHA, and depending on `Stack#sync_github`/continuous-delivery configuration this can trigger commit syncing and downstream automatic deploy/rollback task creation against a victim's stack that the attacker has no legitimate GitHub write access to and no Shipit account or `ApiClient` token for — an unauthorized cross-organization/cross-repository write into another tenant's deployment pipeline. This matches the in-scope Critical impact category "cross-repository writes, or an unauthorized deploy, rollback."

### Likelihood Explanation
Exploitability requires only that the attacker control (or be a legitimate customer/tenant of) any organization configured in the same multi-tenant Shipit instance with its own valid `webhook_secret` — no privileged Shipit account, GitHub App private key, or victim credentials are required. This is a realistic configuration for any Shipit deployment serving more than one GitHub organization, as documented by the sample multi-org `secrets.yml`.

### Recommendation
`verify_signature` and every `Webhooks::Handlers::Handler` subclass must agree on a single, consistently-derived repository identity. Either:
- Verify the signature per-organization using the same field the handlers use to resolve the target repo (`repository.full_name`'s owner segment) instead of `repository.owner.login`/`organization.login`, or
- After signature verification, explicitly assert that `repository.owner.login` (the field used to select the webhook secret) matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Attacker legitimately owns/administers GitHub organization `attacker-org`, which is configured in Shipit's `secrets.yml` with its own `webhook_secret` (a normal multi-tenant setup as shown in `config/secrets.development.shopify.yml`).
2. Attacker crafts a JSON body for the `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over this exact raw body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verification succeeds because the attacker legitimately knows that secret [1](#0-0) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("victim-org/victim-repo")` [3](#0-2) , and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack [8](#0-7) , entirely bypassing any authentication tied to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
