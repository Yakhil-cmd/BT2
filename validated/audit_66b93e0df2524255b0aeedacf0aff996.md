### Title
Webhook signature verification is scoped by an unverified `repository.owner.login`/`organization.login` field while handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the inbound signature against by reading an unverified field straight out of the raw JSON payload (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, the event handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`) act on a *different* field of that same unverified payload — `repository.full_name` — to decide which `Stack`/`Repository`/`Commit` to mutate. Nothing binds the "owner used to pick the verification secret" to the "repository actually written to."

### Finding Description
The equality the code implicitly assumes, but never enforces, is:

`organization used to verify HMAC(payload) == organization that owns the repository the handler mutates`

In `verify_signature`:
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

`repository_owner` is read from the attacker-controlled JSON body before the signature has been checked. It is used purely to look up which per-organization `webhook_secret` (`Shipit.github(organization: ...)`) should be used to verify the HMAC, per `GitHubApp#verify_webhook_signature`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [2](#0-1) 

Once verification succeeds, every handler determines the target repository from a completely different field, `repository.full_name`, via the shared base class:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all use this `stacks`/`repository_name` (or a raw `sha`/`Commit.where(sha:)` lookup) to decide what to change:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 
```ruby
def process
  Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
end
``` [5](#0-4) 
```ruby
def process
  stacks.where(branch: params.check_suite.head_branch).each do |stack|
    stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
  end
end
``` [6](#0-5) 

In any Shipit deployment that hosts multiple GitHub organizations (the engine explicitly supports this — see `config/secrets.development.shopify.yml` defining several independent org sections, each with its own `webhook_secret`), an attacker who legitimately controls one such organization's App/webhook secret (e.g. their own org "X" onboarded onto the same Shipit instance) can:
1. Craft a payload where `repository.owner.login` (or `organization.login`) = `"X"` — the org whose secret they know.
2. Set `repository.full_name` (and `sha`, `after`, `check_suite.head_sha`) to reference a *victim* org/repo/commit tracked by the same Shipit instance.
3. Sign the raw body with org X's known webhook secret and send it to `/webhooks`.

`verify_signature` looks up `Shipit.github(organization: "X")`, computes the HMAC with X's secret, and it matches — verification succeeds. `Shipit::Webhooks.for_event(event)` then processes the payload's `repository.full_name`/`sha`/`check_suite.head_sha`, which point at the victim's stack, entirely bypassing the intended per-organization isolation of webhook trust. [7](#0-6) 

### Impact Explanation
This breaks a cross-repository trust boundary: an org-A-authorized signer can cause writes to org-B's stacks/commits.
- Via `PushHandler`, the attacker can enqueue `GithubSyncJob`/`sync_github` for the victim's stack with an attacker-chosen `expected_head_sha`, forcing an out-of-band sync.
- Via `StatusHandler`, the attacker can inject arbitrary commit statuses (`create_status_from_github!`) onto a victim commit — including a forged "success" CI status, which the README documents as gating merges/deploys (`ci.require`/`ci.blocking`). This can be used to unblock a deploy or merge-queue merge that should have been blocked by real CI.
- Via `CheckSuiteHandler`, it can force `schedule_refresh_check_runs!` on a victim's commit.

This matches the "cross-repository writes" / "unauthorized deploy or merge" impact bar, since a party with no authorization over the victim organization can make the engine act as if a trusted event occurred on the victim's repository.

### Likelihood Explanation
Requires the Shipit instance to be configured to serve more than one GitHub organization (explicitly supported and documented pattern, e.g. `config/secrets.development.shopify.yml`), and requires the attacker to control (or know the webhook secret of) at least one of those organizations — which does not require any privileged access to the victim organization or a Shipit session/API token. This is a realistic scenario for shared, multi-tenant Shipit deployments used by platform teams onboarding many orgs/teams with self-service GitHub Apps.

### Recommendation
Bind the field used for signature-secret selection to the field the handlers act on: derive `repository_owner` from `repository.full_name`'s owner segment (same field the handlers use) rather than a separate `repository.owner.login`/`organization.login` field, or — after signature verification — re-derive/re-validate that `repository.full_name`'s owner matches the `repository_owner` (and hence the organization/secret) that was used to verify the signature, rejecting the event if they diverge. Alternatively, verify the payload with the secret matching the resolved `Repository`'s actual owning organization instead of a client-supplied owner field.

### Proof of Concept
1. Shipit instance hosts two organizations, `attacker-org` and `victim-org`, each configured under `github:` in secrets with distinct `webhook_secret`s (as in `config/secrets.development.shopify.yml`).
2. Attacker controls a repo/App under `attacker-org` and therefore knows/controls `attacker-org`'s `webhook_secret`.
3. Attacker crafts a `push` payload:
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
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature.
6. `PushHandler.call` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — despite the request never having been signed by `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks.rb (L6-22)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
```
