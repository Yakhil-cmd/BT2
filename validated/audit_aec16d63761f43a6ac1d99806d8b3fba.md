### Title
Webhook signature is verified against `repository.owner.login` while write-actions use the unchecked `repository.full_name` field, enabling cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController` selects which GitHub App/organization secret to use for HMAC verification from one field of the untrusted JSON body (`repository.owner.login`), but the handlers that actually mutate Shipit state select the target `Stack`/`Repository` from a *different*, unverified field of the same body (`repository.full_name`). Nothing enforces that these two fields agree, so a valid signature computed with one organization's `webhook_secret` can be used to smuggle a payload that acts on a completely different organization's repository — the same "verification-granularity mismatch" bug class as the Diamond `isFreezable` issue: a security property (authenticity) is checked against one identifier, but enforcement/action is keyed on a sibling identifier that is never bound to the first.

### Finding Description
The webhook signature check is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`verify_webhook_signature` just checks `HMAC-SHA1(webhook_secret_for(repository_owner), raw_body) == signature`: [2](#0-1) 

Once verification passes, the raw parsed body is dispatched unchanged to event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

But handlers resolve the *target* stack/repository from a different key, `repository.full_name`, with no cross-check against `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

For example, `PushHandler` triggers a GitHub sync/deploy pipeline purely off this unverified `full_name`:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

On a legitimate GitHub-generated payload, `repository.owner.login` is always a prefix of `repository.full_name`, so this discrepancy never surfaces. But Shipit's endpoint accepts an attacker-controlled raw JSON body authenticated only by HMAC — nothing in Rails/Shipit re-derives or validates that `full_name` starts with `owner.login`. In a multi-organization Shipit deployment (a documented, supported configuration where each org has its own `app_id`/`webhook_secret`, see `config/secrets.development.example.yml`) [6](#0-5) , an attacker who legitimately owns/administers **one** onboarded, low-privilege organization (and therefore knows or can trigger its real `webhook_secret` via their own GitHub App installation) can:
1. Set `repository.owner.login` to their own org (`"attacker-org"`) so `verify_signature` selects and validates against `attacker-org`'s real secret — passing verification.
2. Set `repository.full_name` to `"victim-org/victim-repo"` so the handler operates on a stack that belongs to a completely different, non-consenting organization.

### Impact Explanation
This breaks the intended equality "organization whose signature authenticated the request == organization whose repository is acted upon." With a push event, this can force a `GithubSyncJob`/`sync_github` cycle and spoofed deploy-readiness signal on a victim stack the attacker's org never controls, and `status`/`check_suite` handlers can inject fabricated CI results using the same technique, since they too resolve `stacks` via `repository.full_name` without validating it against the verified `repository.owner.login`. Because CI status directly gates whether a commit is `deployable?` in Shipit's UI/API, this enables an unauthorized user (any operator of one onboarded org) to unlock a deploy button for a victim organization's stack — an unauthorized-deploy precondition, and in multi-org merge-queue/pull_request handlers, potentially forged merge-queue state changes on a repository outside the attacker's authorization scope. This lands in the "High"/"Critical" impact band defined by the rules (escalation across a repository-write trust boundary via a forged, signed-looking webhook).

### Likelihood Explanation
Requires: (a) the host application to run Shipit's documented multi-organization GitHub configuration, and (b) the attacker to legitimately control at least one onboarded organization's GitHub App/webhook secret (a normal, unprivileged tenant of the Shipit instance — not privileged access to the victim org, no Shipit session, no `ApiClient` token). Given Shipit explicitly documents and supports multiple orgs sharing one instance, this is a realistic deployment shape, and exploitation only requires crafting a raw HTTP POST with a self-computed HMAC — no social engineering or host compromise needed.

### Recommendation
After signature verification succeeds, re-derive the trusted organization identity strictly from the field just used to select the secret (`repository.owner.login`), and require that every handler's target repository (`repository.full_name`) be prefixed by that same, already-authenticated owner login before it is used to look up any `Stack`/`Repository`. Reject the webhook (422) if the two disagree, establishing the same organization↔repository binding for both verification and mutation, analogous to establishing the 1:1 facet↔freezable binding in the referenced fix.

### Proof of Concept
Given a Shipit instance configured with two orgs, `attacker-org` (secret `S_A`, attacker controls the real GitHub App for this org) and `victim-org` (has a stack `victim-org/victim-repo` configured in Shipit):

```
body = {
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", S_A, body)

POST /webhooks
X-Github-Event: push
X-Hub-Signature: <signature>
Body: <body>
```
`verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and validates the HMAC against `S_A` — which the attacker legitimately possesses — so verification passes. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack, despite the request never having been authenticated by `victim-org`'s own secret. [1](#0-0) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
