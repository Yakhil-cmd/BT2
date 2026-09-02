### Title
Webhook signature verification selects the trusted organization from an unverified payload field, while event handlers act on a different unverified payload field for repository targeting - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-tenant Shipit deployment (multiple GitHub organizations, each with its own `webhook_secret`, as shown in `config/secrets.development.shopify.yml`), the webhook signature check binds trust to the organization derived from `repository.owner.login` in the raw, unverified JSON body, while the handlers that actually mutate state bind their target `Stack`/`Repository` to `repository.full_name` — a separate, independently attacker-controlled field in that same unverified body. Because the HMAC only proves "this body was signed with *some* org's secret", not "the org that signed it owns the repository being acted upon," an attacker who legitimately controls the webhook secret for Org A can forge a payload whose `repository.full_name` points at Org B's tracked repository.

### Finding Description
`WebhooksController#verify_signature` looks up the GitHub App/secret to validate against using a field taken straight from the JSON body, before the body's authenticity is established: [1](#0-0) [2](#0-1) 

`repository_owner` falls back to `organization.login` if `repository.owner.login` is absent — both are ordinary JSON keys with no cryptographic relationship to `repository.full_name`.

Once the signature is accepted (because it matches whichever organization's secret `repository_owner` happened to select), event handlers derive the actual target `Stack` from a *different* field of the same untrusted body: [3](#0-2) 

For example, `PushHandler` uses that `stacks` scope (derived from `repository.full_name`) to trigger a GitHub sync with an attacker-controlled `expected_head_sha`: [4](#0-3) 

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization/repository that the handler writes to`

Instead, the code enforces only:
`organization whose webhook_secret authenticated the request == repository.owner.login field in the body`
and separately:
`repository/stack acted upon == repository.full_name field in the same, unverified body`

Nothing ties `repository.owner.login` to `repository.full_name`; both are arbitrary values chosen by whoever crafts the POST body. A multi-tenant Shipit instance configures a distinct `webhook_secret` per organization (see the fixture below), meaning knowledge of one org's secret should not authorize writes to another org's tracked repositories: [5](#0-4) 

### Impact Explanation
An attacker who legitimately administers (or has otherwise obtained) the GitHub webhook secret for **one** organization configured in a shared/multi-tenant Shipit instance can craft a raw POST body where:
- `repository.owner.login` (or `organization.login`) = the attacker's own org (so `verify_webhook_signature` validates against a secret the attacker knows and can compute a correct HMAC for), and
- `repository.full_name` = `"victim-org/victim-repo"` (a completely different, unrelated tracked repository whose secret the attacker does not know).

The signature check passes, and the event is dispatched to handlers, which resolve the affected `Stack` purely from `repository.full_name`. This lets the attacker forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events against a victim organization's stacks without ever knowing the victim's webhook secret — e.g. triggering `Stack#sync_github` with a forced `expected_head_sha`, injecting fabricated commit statuses/check runs that make a commit appear CI-passing (enabling an unauthorized deploy via continuous deployment or an unauthorized PR merge via the merge queue), or manipulating team membership tied to another org. This is a cross-repository/cross-organization write and can lead to an unauthorized deploy or merge, matching the Critical bucket.

### Likelihood Explanation
This requires the attacker to be a legitimate holder of a webhook secret for *any one* organization tracked by the shared Shipit instance (a realistic setup per the multi-org secrets template) but explicitly *not* the target organization. No GitHub App private key, `GITHUB_TOKEN`, or Shipit session/API token is required — only the ability to send an arbitrary raw HTTP POST to the public `/github/webhooks` endpoint with a correctly computed HMAC for the attacker's own org secret and a crafted `repository.full_name` pointing elsewhere. This is a purely unprivileged-attacker path once one org boundary is compromised or self-controlled, matching the "organization that authenticated versus the repository that is written" binding this task calls out.

### Recommendation
Bind the org used to select/verify the webhook signature and the org/repository the handler acts upon to the *same, single* verified value. Concretely: derive `repository_owner` (used for secret selection) and the "acting" repository from the same field of the payload, and after signature verification, re-validate that the resolved `Stack`'s `Repository#owner` actually matches the organization whose secret validated the signature before dispatching to any handler.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `attacker-org` and `victim-org`, each with a distinct `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that org's GitHub App/webhook).
3. Attacker crafts a JSON body:
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
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org-secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s app/secret, and the HMAC validates successfully.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `victim-org`'s stack — despite the attacker never possessing `victim-org`'s webhook secret.

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
