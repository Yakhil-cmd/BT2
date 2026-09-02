### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field, allowing cross-organization/repository webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
This mirrors the `takeUSDCRaised()` bug class: two values that are supposed to represent "the same thing" (decimal-adjusted amount vs. raw balance) are taken from different, unsynchronized sources, so a check performed on one value silently authorizes an action performed with the other. In `WebhooksController`, the HMAC signature is verified using a secret selected by `repository_owner` (parsed from the payload's `repository.owner.login`, or `organization.login`), while the handlers that actually mutate application state select the target `Repository`/`Stack` using a completely different, unchecked payload field: `repository.full_name`.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/secret to validate the request against solely from an attacker-supplied field in the (as yet unverified) JSON body: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring multiple independent GitHub Apps/organizations, each with its own `webhook_secret`: [3](#0-2) 

Once the signature check passes (using the secret tied to `repository_owner`), the raw payload is dispatched to handlers, and `create` never re-validates that `repository_owner` corresponds to the repository actually acted upon: [4](#0-3) 

The base `Handler` class, used by `PushHandler` and other handlers, resolves the target `Repository`/`Stack` from a *different* field, `repository.full_name`, which is never cross-checked against `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because the HMAC is only checked against the secret keyed by `repository_owner`, and that secret is entirely attacker-controlled if the attacker administers their own org/App in the same multi-tenant Shipit deployment, an attacker can self-sign a payload with `repository.owner.login` set to their own org (so the correct/known secret is selected) while setting `repository.full_name` to a victim organization's repository (which is what handlers actually act on). Nothing in the code enforces the equality:

`organization authenticated by signature == organization/repository whose Stacks are mutated`

### Impact Explanation
This breaks a deployment-trust binding explicitly in scope: *"an organization that authenticated versus the repository that is written."* Any handler keyed off `repository.full_name` (or, for the `membership` event, off the `organization`/`team` sub-objects, which are likewise not cross-validated against the signing owner) can be triggered cross-organization:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for **any** stack scoped to the attacker-chosen `repository.full_name`, effectively spoofing a push event and forcing a sync to an arbitrary attacker-chosen SHA on a repository/organization the attacker does not own or have GitHub-side push access to. If `continuous_deployment` is enabled on that stack, this can trigger an unauthorized deploy of a chosen revision.
- `MembershipHandler`/`StatusHandler`/other handlers can similarly be invoked against victim organizations/teams using only knowledge of the attacker's own org's webhook secret.

This satisfies the "unauthorized deploy" / cross-repository-write impact bar defined in scope.

### Likelihood Explanation
The prerequisite is that the Shipit deployment is configured for more than one GitHub organization/App (a documented, supported configuration, see `config/secrets.development.example.yml` above), and that the attacker administers (or has been granted install access to) one of those orgs/Apps — giving them legitimate knowledge of that org's `webhook_secret` without any special Shipit credential, session, or admin access. Given that Shipit's own docs advertise multi-org support as a first-class feature, this is a realistic configuration, making the likelihood moderate-to-high in multi-tenant deployments.

### Recommendation
After signature verification succeeds, re-derive the organization/owner strictly from the same field(s) the handlers use to select the target `Repository`/`Stack` (i.e., `repository.full_name`'s owner segment, or the relevant `organization.login`), and reject the request if it doesn't match the `repository_owner` that was used to select the verification secret. Alternatively, verify the signature using the secret tied to the resolved `Repository`'s configured organization rather than a field that is independent from what handlers ultimately act upon.

### Proof of Concept
1. Attacker configures/administers `attacker-org` as one of the organizations recognized by the target Shipit instance's `config/secrets.yml`, and thus knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a JSON body:
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
3. Attacker computes `X-Hub-Signature` as `sha1=HMAC(attacker-org_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret [1](#0-0) .
5. `PushHandler#process` (via `Handler#repository_name`) resolves stacks using `repository.full_name = "victim-org/victim-repo"` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for stacks under the victim org/repo [7](#0-6) , despite the attacker never having any GitHub-side relationship with `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
