## Title
Webhook secret selection keyed on `repository.owner.login` while stack/repository resolution is keyed on `repository.full_name` allows cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

## Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an inbound webhook against using `repository_owner`, extracted from `params.dig('repository', 'owner', 'login')` of the untrusted payload itself. [1](#0-0)  Once the signature is accepted, every `Handler` subclass resolves the actual `Repository`/`Stack` to mutate using a *different* field of the same payload: `payload.dig('repository', 'full_name')`. [2](#0-1)  Nothing ties these two fields together, so the "organization whose secret authenticated this webhook" and "the repository whose Stack is actually written to" are independent, attacker-controlled values inside the same signed body.

## Finding Description
This mirrors the `Controller.sol` bug class: a value is checked/verified (nonce validated against `order.payer`) but a *different* value is recorded/acted upon (`nonces[signer]`). Here:

- Verification key: `repository_owner` = `params.dig('repository','owner','login')` (or `organization.login`) — used to pick the `Shipit.github(organization:)` instance and its `webhook_secret` for HMAC verification. [3](#0-2) 
- Action key: `repository_name` = `payload.dig('repository','full_name')` — used by every webhook `Handler` (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) via `Handler#stacks`/`Repository.from_github_repo_name` to find the `Stack`/`Repository` object that gets mutated. [2](#0-1) 

Because both fields are read straight out of the attacker-supplied JSON body, and only their *presence inside a correctly-signed body* is checked (not their mutual consistency), an attacker who legitimately controls one configured GitHub organization/App in a Shipit deployment (Shipit explicitly supports multiple GitHub orgs/apps, see `test/dummy/config/secrets_double_github_app.yml`) [4](#0-3)  can compute a valid HMAC signature for their own org's webhook secret while setting `repository.full_name` to point at a repository/stack belonging to a completely different, victim organization. `verify_webhook_signature` only checks that the signature matches the secret picked via `repository.owner.login`; it never checks that `repository.full_name`'s owner segment matches that same login. [5](#0-4) 

The equality that should hold but doesn't:
`organization that authenticated the signature (repository.owner.login)` == `organization that owns the repository/stack actually written (repository.full_name)`

## Impact Explanation
Once past `verify_signature`, handlers act on payload data believing it originates from the real owner of the targeted repository:
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha: params.after)` for any stack matching the attacker-chosen `full_name`+`branch`, forcing a re-sync/deploy pipeline trigger on a stack the attacker does not own. [6](#0-5) 
- `StatusHandler#process` writes a `Commit#create_status_from_github!` record with attacker-controlled `state`/`context`/`description`/`target_url` for any commit sha, which can flip CI/CD gating status used to decide whether Shipit allows a deploy to proceed, on a victim's stack. [7](#0-6) 
- `MembershipHandler` similarly creates/mutates `Team`/`User` records based on attacker-controlled `organization`/`team`/`member` fields once any valid signature is presented, independent of which org's key signed it. [8](#0-7) 

This is a cross-organization/cross-repository write: an attacker administering one legitimately-registered (but low-trust) GitHub organization in a multi-tenant Shipit instance can forge push/status/membership events attributed to any other organization's repositories, influencing deploy triggers and commit status gating on stacks they do not control.

## Likelihood Explanation
Requires only that the attacker be the administrator of *some* GitHub organization/App that is configured in the Shipit instance's `github:` secrets (a legitimate but low-privilege position in a multi-org deployment, as explicitly supported per `secrets_double_github_app.yml`). No Shipit session, API token, or GITHUB private key of the victim org is needed — the attacker uses their own legitimate webhook secret and simply crafts the JSON body's `repository.full_name` to point elsewhere.

## Recommendation
After signature verification, enforce that the organization used to select the verifying secret matches the owner segment of `repository.full_name` (and `organization.login` where present) before any `Handler` is invoked — i.e., derive both `repository_owner` and `repository_name` once, verify `repository_name.split('/').first == repository_owner`, and reject (422) on mismatch. Alternatively, pass the verified organization identity into `Handler.call` and have `Handler#stacks` scope `Repository.from_github_repo_name` lookups to repositories owned by that verified organization.

## Proof of Concept
1. Shipit is configured with two GitHub orgs/apps, `AttackerOrg` (attacker administers this, knows its `webhook_secret`) and `VictimOrg` (has a stack `VictimOrg/prod-app` tracked in Shipit), per the multi-org config pattern shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/prod-app"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(AttackerOrg_webhook_secret, body)` — a signature they can legitimately produce since they own `AttackerOrg`'s app.
4. POST to `/webhooks` with header `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: 'AttackerOrg')` and successfully verifies the signature against the attacker's own secret. [9](#0-8) 
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `Handler#stacks` resolves `Repository.from_github_repo_name('VictimOrg/prod-app')` — a repository owned by `VictimOrg`, not `AttackerOrg` — and triggers `sync_github` on it. [2](#0-1) [6](#0-5) 

Note: I could not fully trace `Shipit.github(organization:)`'s app-selection implementation or `Repository.from_github_repo_name`'s exact lookup logic within the available context (index truncation on `lib/shipit.rb`/`app/models/shipit/repository.rb`); confirming the precise multi-org config wiring in a live deployment would benefit from a full Devin session with complete file access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```
