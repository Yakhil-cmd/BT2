### Title
Webhook signature verified against the wrong organization's secret, allowing cross-repository writes into stacks owned by a different GitHub organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `repository_owner`, which is read from the untrusted, not-yet-verified JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). The event handlers that subsequently act on the same payload (e.g. `PushHandler`) resolve the target repository from a *different* field of that same payload: `payload.dig('repository', 'full_name')`. These two fields are never cross-checked against each other.

### Finding Description
`verify_signature` picks the app config to validate against like this: [1](#0-0) 
and `repository_owner` is derived purely from attacker-controlled JSON: [2](#0-1) 

Once the signature check passes, `create` dispatches the raw, attacker-controlled JSON to the registered handlers for the event without any further binding to the organization used for verification: [3](#0-2) 

The `PushHandler` (and other handlers) resolve which `Stack`/`Repository` to act on from `repository.full_name` in that same JSON body: [4](#0-3) [5](#0-4) 

Because Shipit supports multiple GitHub Apps/organizations, each with its own `webhook_secret` (as documented in `config/secrets.development.example.yml`), the equality that must hold is:

`organization whose webhook_secret authenticated the request == organization that owns the repository being written to`

In this codebase that equality is never enforced: the field used to pick the HMAC secret (`repository.owner.login` / `organization.login`) and the field used to select the repository/stack to mutate (`repository.full_name`) are independent JSON keys inside the same attacker-supplied payload, and nothing requires them to agree.

### Impact Explanation
An attacker who controls (or has compromised) one GitHub organization/App integrated with this Shipit instance knows that organization's `webhook_secret` (e.g., because they installed their own GitHub App pointing at this same Shipit instance, a supported and documented configuration — see `config/secrets.development.example.yml`'s multi-org example). They can craft a webhook payload where:
- `repository.owner.login` (or `organization.login`) = their own controlled org (so `Shipit.github(organization: repository_owner)` picks their known secret and `verify_signature` succeeds), and
- `repository.full_name` = `"victim-org/victim-repo"` (an unrelated repository/stack actually configured in this Shipit instance).

Since the signature is computed over the raw body with their own valid secret, the request passes `verify_signature`, and then `PushHandler#stacks` looks up the stack via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, i.e. the victim org's repository, and triggers `stack.sync_github(expected_head_sha: ...)`, which drives an unauthorized sync/deploy pipeline for a repository the attacker does not control. This breaks the deployment-trust binding between the authenticating organization and the repository being written to, and results in unauthorized cross-organization/cross-repository actions triggered on Shipit's git sync/deploy pipeline — satisfying the "cross-repository writes / unauthorized deploy" high-impact criteria.

### Likelihood Explanation
Likelihood is Medium-High in any deployment that has more than one GitHub organization/App configured against the same Shipit instance (a supported, documented configuration). No privileged Shipit account, `ApiClient` token, or session is required — only the ability to send a webhook signed with a secret for *any one* org integrated with the instance (which the attacker legitimately possesses if they administer that org's GitHub App). The attack requires only crafting two independent JSON fields in a single POST to `/webhooks`.

### Recommendation
After signature verification succeeds, re-derive the organization from the same field used for repository resolution (`repository.full_name`'s owner segment) and require it to match the organization whose secret validated the signature. Alternatively, always verify webhook signatures against the app config resolved from `repository.full_name`'s owner, not from a separately-controllable `repository.owner.login` / `organization.login` field, and reject the request if it does not match a repository/stack actually owned by the authenticating organization's App installation.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/orgs, e.g. `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (multi-org config as shown in `config/secrets.development.example.yml`).
2. Attacker knows `attacker-org`'s `webhook_secret` (they control that GitHub App/org).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, raw_body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature validates successfully.
6. `create` invokes `PushHandler`, which resolves the target via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, finds the corresponding `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — an action on a repository/org the attacker does not own, authenticated only by a secret belonging to a different, unrelated org.

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
