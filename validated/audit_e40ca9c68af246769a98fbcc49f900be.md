### Title
Webhook signature is verified against the org named in `repository.owner.login`, but the event is executed against the repository named in `repository.full_name` — allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App/webhook secret to validate an incoming webhook against using one JSON field (`repository.owner.login`), but every event handler resolves the actual repository/stack to act on using a *different* JSON field (`repository.full_name`) from the same attacker-controlled body. Because these two fields are never checked for consistency, an actor who legitimately knows the webhook secret for *their own* configured GitHub organization can forge a signed payload that is verified as "from org A" but whose `repository.full_name` points at a stack belonging to org B.

### Finding Description
`verify_signature` picks the app config strictly from the payload: [1](#0-0) 
and `repository_owner` is derived from: [2](#0-1) 

The HMAC signature only proves that the request body was produced by someone who knows the `webhook_secret` configured for the organization named at `repository.owner.login` — nothing more. Shipit explicitly supports multiple independent GitHub App configs, one per organization, each with its own `webhook_secret` known to whoever set up that org's integration, as documented in the multi-org config schema: [3](#0-2) 

Once the signature check passes, `create` dispatches the *entire attacker-controlled JSON body* (not just the verified org) to the handlers: [4](#0-3) 

Every handler resolves the target repository/stack from a completely different field, `repository.full_name`, which is never cross-checked against `repository.owner.login`: [5](#0-4) 

For example, `PushHandler` uses this to look up stacks and trigger `sync_github`: [6](#0-5) 

This is the exact analog of the `depositAndFix` bug class: the verified/authenticated value (`repository.owner.login`, checked against the signature) is not the value the privileged operation actually acts on (`repository.full_name`, used to select the stack). The equality that should hold — "organization whose secret authenticated this request" == "organization owning the repository the handler mutates" — is never enforced.

### Impact Explanation
An operator of any one Shipit-configured GitHub organization (who knows that org's `webhook_secret`, as set up per `docs/setup.md`) can forge webhook deliveries (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) targeted at stacks belonging to any *other* organization configured in the same Shipit instance, by setting `repository.owner.login` to their own org (to pass signature verification) and `repository.full_name` to the victim org/repo. This enables cross-repository writes: spoofed commit `status`/`check_suite` updates that affect a victim stack's deploy-readiness gating, forged `push` events that trigger `sync_github` against a victim's stack, and forged `pull_request`/`membership` events that mutate unrelated stack/team state — all without any credential belonging to the victim organization.

### Likelihood Explanation
Requires only that the attacker be a legitimate administrator of one org configured in a multi-tenant Shipit deployment (a realistic, documented deployment topology per `config/secrets.development.example.yml`), with no special access to the victim org, no Shipit session, and no API token — it is purely a crafted HTTP POST to the public webhook endpoint with a correctly computed HMAC using their own known secret.

### Recommendation
After verifying the signature with the secret selected via `repository.owner.login`/`organization.login`, re-validate that the same organization matches the owner segment of `repository.full_name` before dispatching to any handler, rejecting the request otherwise.

### Proof of Concept
1. Shipit is configured with two orgs, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (per `config/secrets.development.example.yml`).
2. Attacker controls `orgA` and knows `orgA`'s `webhook_secret`.
3. Attacker crafts a `status` (or `push`) webhook payload body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "repository": {
    "owner": {"login": "orgA"},
    "full_name": "orgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POSTs to `/github/webhooks`.
5. `verify_signature` looks up `Shipit.github(organization: 'orgA')` (from `repository.owner.login`) and successfully verifies the signature using the known `orgA` secret — `app/controllers/shipit/webhooks_controller.rb:24-30`.
6. `create` dispatches the full payload to `Shipit::Webhooks.for_event('status')`, whose handler resolves the target repo via `payload.dig('repository', 'full_name')` = `"orgB/victim-repo"` — `app/models/shipit/webhooks/handlers/handler.rb:36-38` — and updates status/state for a stack the attacker does not own or control.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
