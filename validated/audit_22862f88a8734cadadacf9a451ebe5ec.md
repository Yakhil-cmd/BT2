### Title
Webhook signature is bound to an attacker-selectable organization while `StatusHandler` writes commit status by SHA with no repository check, enabling cross-repository status forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` is used to validate the inbound HMAC based on a value read directly out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`), not out of a value cryptographically tied to which record the event will subsequently mutate. [1](#0-0) [2](#0-1) 

Downstream, `Shipit::Webhooks::Handlers::StatusHandler#process` updates commit status purely by matching `sha` across the **entire** `Commit` table, with no scoping to the organization/repository whose secret validated the request: [3](#0-2) 

This is the same bug class as the report: a key/identifier read from the payload for one purpose (choosing the signing secret / authorization scope) is not the same key used to select the record that is actually written, so an attacker who controls *any* one organization's signing secret can act on records belonging to a completely different repository/organization.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both values are attacker-supplied fields inside the same JSON body whose HMAC is being checked. [4](#0-3) 

Each configured GitHub organization in Shipit has its own independent `webhook_secret`, `oauth` credentials, etc. (see `test/dummy/config/secrets.test.json` structure), and `Shipit.github(organization:)` looks the correct config up by that same `login` string. So the HMAC only proves "this payload was signed with the secret configured for whichever organization login the attacker put in the payload" — it proves nothing about the `repository.full_name` field that handlers later use, nor about the `sha` field `StatusHandler` uses.

`StatusHandler` then does:
```ruby
Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
```
with no `repository`/`stack` filter at all. [5](#0-4) 

Compare `Handler#stacks`, which correctly scopes by `repository.full_name`: [6](#0-5) 
`StatusHandler` does not use this scoping helper at all — it is the odd one out among handlers.

Equality that should hold but doesn't:
`organization whose secret authenticated the request == organization that owns the commit record being mutated`.
In the current code, the left side is attacker-chosen (any organization login present in the JSON body, so long as the attacker also possesses/controls that organization's webhook secret through their own legitimate Shipit configuration), while the right side is determined purely by an unscoped `sha` lookup across all stacks/repositories in the Shipit instance.

### Impact Explanation
Any party who legitimately controls a webhook signed with **one** configured organization's secret (e.g., they administer their own GitHub App/organization that is configured in this Shipit instance, a normal, unprivileged setup for a multi-tenant Shipit deployment) can forge a `status` event:
```json
{
  "organization": {"login": "attacker-org"},
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/decoy"},
  "sha": "<victim commit sha in a different organization>",
  "state": "success",
  "context": "ci/required-check"
}
```
signed with `attacker-org`'s webhook secret. `verify_signature` passes because it picks `attacker-org`'s secret to validate. `StatusHandler` then writes a forged `success` status onto the victim's commit, in a repository/organization the attacker has no permission on at all. Since Shipit gates deploy eligibility and CI blocking behavior on commit statuses (`ci.blocking` / merge queue checks), this can be used to make an otherwise-blocked commit appear deployable/mergeable, i.e. an unauthorized deploy/merge — the impact category explicitly listed as Critical/High in scope.

### Likelihood Explanation
Requires the attacker to control a valid signature for at least one organization configured in this Shipit instance (their own org, if they self-configure their own GitHub App against a shared/multi-tenant Shipit deployment, which is a normal deployment pattern for this engine and not a privileged trust relationship with the victim org). It also requires knowing the target commit's SHA, which is typically discoverable (public GitHub commit SHAs, PR pages, CI logs) without needing access to the victim's Shipit instance UI. No `ApiClient` token, session, or GitHub App private key for the *victim* org is needed — only a valid signature for the attacker's *own* configured organization.

### Recommendation
`StatusHandler` (and any other handler using unscoped lookups) must scope the affected record to the repository/organization whose secret validated the request, e.g. resolve the target commit through `stacks`/`Repository.from_github_repo_name(repository_name)` (as `Handler#stacks` already does) rather than a global `Commit.where(sha:)`. Additionally, `WebhooksController#verify_signature` should re-derive `repository_owner` from the same value used later for repository resolution (`repository.full_name`'s owner) rather than trusting a separate, independently attacker-controlled field, and should reject events whose `organization.login` and `repository.owner.login` disagree.

### Proof of Concept
1. Attacker configures/administers `attacker-org`, a legitimate organization onboarded onto the shared Shipit instance, and therefore knows/controls `attacker-org`'s `webhook_secret`.
2. Attacker obtains the SHA of a commit belonging to `victim-org/victim-repo` (public GitHub commit page).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
   ```json
   { "organization": {"login": "attacker-org"},
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/decoy"},
     "sha": "<victim-sha>", "state": "success", "context": "ci/required-check" }
   ```
   and `X-Hub-Signature` computed with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC validates. [1](#0-0) 
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which finds `Commit.where(sha: "<victim-sha>")` in `victim-org/victim-repo` and writes the forged `success` status onto it. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
      end
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
