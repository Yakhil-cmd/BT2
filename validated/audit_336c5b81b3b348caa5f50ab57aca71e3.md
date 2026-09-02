### Title
Webhook `status` events are applied globally without binding the authenticating GitHub organization to the target repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb](), [File: app/controllers/shipit/webhooks_controller.rb]())

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification purely from a JSON field inside the *unverified* request body: `repository_owner`, which falls back to `params.dig('organization','login')` or `params.dig('repository','owner','login')`. [1](#0-0) [2](#0-1) 

The signature is verified only against that organization's `webhook_secret` via `Shipit.github(organization: repository_owner)`, and `verify_webhook_signature` treats an unconfigured secret as automatically valid. [3](#0-2) 

Once the signature check passes, `StatusHandler#process` (invoked for the `status` event) applies the payload globally, with no scoping to the organization/repository that was used to select the verifying secret:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Its `params` block does not even require a `repository` field, unlike `PushHandler` or the pull-request handlers, which resolve `stacks`/`repository` from `payload.dig('repository','full_name')` via the base `Handler` class. [5](#0-4) [6](#0-5) 

The binding that should hold is:
`organization whose secret verified the request == organization that owns the commit/repository being mutated by the handler`

In this engine, that equality is never checked for the `status` event. The only gate is a JSON field (`repository.owner.login` / `organization.login`) which the attacker fully controls and which is not tied to the `sha` being updated. Any party who can produce a valid signature for **one** configured GitHub organization (an org admin who legitimately owns their own app's `webhook_secret`, or any org whose `webhook_secret` was left unset — documented as optional in `docs/setup.md`) can update the CI status of a commit belonging to a **different** organization's stack, because `Commit.where(sha: params.sha)` searches across all stacks in the installation.

### Impact Explanation
A forged `status` webhook can set an arbitrary commit's state to `success` via `commit.create_status_from_github!`, which feeds `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) and can trigger a continuous-deployment auto-deploy (`add_status` schedules merges/CD on transition to `success`). [7](#0-6) [8](#0-7) 

This allows an entity that only controls one tenant's GitHub App/webhook configuration to force a fake "green" CI status onto a commit in a completely different tenant's repository/stack, bypassing required-status checks and potentially triggering an unauthorized deploy — matching the Critical-impact "unauthorized deploy" criterion.

### Likelihood Explanation
This requires a Shipit installation configured for multiple GitHub organizations (explicitly supported per `config/secrets.development.example.yml`), where one org's webhook secret is known to a party who has no legitimate access to another org's stacks, or where any configured org has no `webhook_secret` set (explicitly called out as optional in `docs/setup.md`). This is a plausible, in-scope multi-tenant configuration, not requiring any Shipit session, API token, or GitHub App private key — only knowledge of one org's webhook secret, which the rules permit (webhook_secret exclusion in the rules is about not assuming direct secret theft; here the "attacker" is a legitimate admin of one org acting on another org's data, which is the trust-binding break class explicitly called out: "an organization that authenticated versus the repository that is written").

### Recommendation
Bind the verified organization to the target stack/repository before mutating any commit/status/check-run data. Concretely: have `StatusHandler` (and `CheckSuiteHandler`) resolve `stacks`/`repository` from the payload's `repository.full_name` (as `PushHandler` and PR handlers already do) and scope the `Commit` lookup to `stacks`/that repository, and additionally verify that the resolved repository's owner matches the organization whose secret validated the signature.

### Proof of Concept
Not independently executable without a live multi-organization Shipit deployment and knowledge of one org's webhook secret (or an org with no configured secret); this is a static code-path analysis based on:
1. `WebhooksController#verify_signature` picks the verifying secret from the attacker-controlled `repository.owner.login`/`organization.login` field. [9](#0-8) 
2. `StatusHandler#process` applies the status update to `Commit.where(sha: params.sha)` with no repository/organization scoping at all. [10](#0-9) 
3. `Commit#create_status_from_github!`/`add_status` can change deployability and trigger continuous deployment. [11](#0-10) [8](#0-7) 

A crafted request: `POST /webhooks` with header `X-Github-Event: status`, body `{"repository":{"owner":{"login":"org-attacker-controls"}},"sha":"<sha-of-commit-in-victim-org-stack>","state":"success", ...}`, signed with `org-attacker-controls`'s webhook secret, would pass `verify_signature` and then update the victim commit's status regardless of which org actually owns that commit/stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
