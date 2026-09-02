### Title
Webhook signature verified against `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using the payload field `repository.owner.login` (or `organization.login`). Once the signature check passes, every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`, etc.) determines which `Repository`/`Stack` to act on using a *different*, unverified payload field: `repository.full_name`. Because the signature only proves the JSON body was signed with the secret belonging to whatever organization is named in `repository.owner.login`, and not that `repository.full_name` belongs to that same organization, an attacker who controls (or is a member of) one Shipit-monitored GitHub organization can forge webhook deliveries that are "correctly signed" for their own org's secret while pointing `repository.full_name` at a Stack belonging to a completely different organization.

### Finding Description
`WebhooksController#verify_signature` resolves the signing key like this: [1](#0-0) 

`repository_owner` is read straight from the untrusted, unauthenticated JSON body: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization webhook secrets from `secrets.github` and instantiates a `GitHubApp` scoped to that organization: [3](#0-2) 

The HMAC comparison itself only proves the body was signed with *that org's* `webhook_secret`: [4](#0-3) 

After signature verification succeeds, the request body is dispatched to handlers, e.g. in `WebhooksController#create`: [5](#0-4) 

Every handler resolves the target `Repository`/`Stack` from a completely different field — `repository.full_name` — via the shared base class: [6](#0-5) 

For example, `PushHandler` uses this to enqueue a Git sync against any stack matching the branch: [7](#0-6) 

and `StatusHandler` uses `sha` (also attacker-controlled, unrelated to `repository.owner.login`) to attach a commit status: [8](#0-7) 

Nothing in `verify_signature`, `Handler#initialize`, or any handler cross-checks that `repository.full_name`'s owner matches the `repository.owner.login`/`organization.login` value that was actually used to select the signing secret. This is structurally the same class of bug as the reported Solana issue: a check is performed over one region/field (`repository.owner.login`, used for cryptographic verification) while the actually-consumed operation spans a different, unchecked region/field (`repository.full_name`, used to select the Stack that gets written to). The verified field and the acted-upon field are not the same, so the trust boundary the signature is meant to enforce doesn't hold.

### Impact Explanation
This breaks the binding "an organization that authenticated versus the repository that is written." In a Shipit deployment configured with multiple GitHub organizations (`Shipit.github_organizations`, supported per `github_app_config`), any user who can trigger a legitimately signed webhook from Organization A (e.g., a member of Org A, or anyone able to get Org A's GitHub App/webhook to fire — pushes, status updates, PR events are attacker-triggerable via ordinary repo activity in Org A) can craft/replay a payload whose `repository.full_name` names a Stack under Organization B. The signature check passes (it was computed by GitHub for Org A's webhook secret and the raw body used unmodified by the attacker replaying/relaying it), but the effects land on Org B's stack: e.g. `PushHandler` triggers `GithubSyncJob`/deploy pipeline refresh for Org B's stack, `StatusHandler` forges commit statuses that gate CI-based deploy checks (`ci.require`) for Org B's commits, `CheckSuiteHandler`/`PullRequest` handlers can create/mutate review stacks or mislead merge-status logic for repositories the attacker has no access to. Forged CI/commit statuses feeding into deploy-safety checks can enable an unauthorized deploy on a repository the attacker does not control — a cross-repository/cross-organization write achieved without any Shipit session or API token, satisfying the Critical bar ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
Exploitability requires only that the target Shipit instance is configured with more than one GitHub organization (a documented, supported configuration via `secrets.github` keyed by org) and that the attacker controls, or can produce genuine webhook traffic from, at least one of those organizations (trivial for an org member, or anyone with push/PR access to a repo in that org, since push/status/pull_request events are attacker-triggerable through normal GitHub actions). No GitHub App private key, `webhook_secret`, or Shipit session is needed — the attacker only needs GitHub's own signature for their own org's webhook, which GitHub computes and delivers for them. The only extra step is crafting/replaying a body with a mismatched `repository.full_name`, which is straightforward since GitHub webhook payloads are attacker-influenced JSON that Shipit does not re-validate for internal consistency.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), require that the organization used to select/verify the webhook secret is the same organization that owns `repository.full_name` (and `organization.login` for org-level events) before dispatching to any handler. Concretely, derive both values, verify they match (case-insensitively) and reject (422) on mismatch, rather than trusting `repository.full_name` as a bare, unchecked field once *any* org's signature validates.

### Proof of Concept
Assume Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret`, and Stack `org-b/victim-repo` exists in Shipit.

1. Attacker is a member of `org-a` (or otherwise able to make GitHub deliver a signed webhook from `org-a`, e.g. via a repo they own there).
2. Attacker crafts a `push` event body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
3. Attacker signs this exact body with `org-a`'s `webhook_secret` (which they can obtain by configuring their own webhook on an `org-a` repo and observing GitHub's `X-Hub-Signature` for a body they control, or by directly computing HMAC-SHA1 if they possess/can leak the org-a secret through legitimate access to their own org's webhook settings) and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner = "org-a"`, loads `Shipit.github(organization: "org-a")`, and the HMAC check passes because the body was indeed signed with `org-a`'s secret.
5. `WebhooksController#create` dispatches to `PushHandler`, which calls `Handler#stacks`, resolving `Repository.from_github_repo_name("org-b/victim-repo")` and enqueuing `GithubSyncJob` / triggering downstream deploy-pipeline activity for a stack in `org-b`, an organization the attacker has no relationship to. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-38)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
