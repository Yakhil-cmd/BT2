## Title
Cross-Repository Commit Status Injection via SHA-Only Lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook is authenticated per-organization (the signature is verified against the webhook secret belonging to the organization/owner derived from the payload), but the handler that consumes the payload writes CI status data to *any* commit in the database that matches the given SHA, without re-checking that the SHA belongs to a repository owned by the authenticated organization. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from the payload itself and validates the HMAC signature against that organization's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves the request was signed by *some* organization configured in `Shipit.github`, and specifically the organization named in `repository.owner.login` (or `organization.login`) of that same payload — a value the attacker controls and that is not cross-checked against which repository's commits get modified.

The `status` event is routed to `StatusHandler`, which processes the event purely by `sha`, with no scoping to the repository/org that was authenticated: [3](#0-2) 

Unlike `PushHandler`, which scopes lookups through `Repository.from_github_repo_name(repository_name)` via the base `Handler#stacks` helper: [4](#0-3) 

`StatusHandler#process` bypasses this repository scoping entirely and does a global `Commit.where(sha: params.sha)` query across the whole `commits` table (which spans all stacks/repositories/organizations known to the Shipit instance), then calls `create_status_from_github!` on every match: [5](#0-4) 

The equality that should hold is: `organization authenticated by signature == owner of repository whose commit status is mutated`. Before the attack, this holds because legitimate GitHub only sends `status` events for the org/repo pair it validly owns. After an attacker with legitimate (but limited) app credentials for **Org A** sends a forged `status` payload naming a `sha` that happens to also exist in a completely unrelated **Org B**'s repository (SHA collision across repos is plausible for common merge/init commits, or the attacker may know a specific SHA present in the target stack because it is public git history), the signature check passes for Org A's secret, yet `Status.replicate_from_github!` writes a new `Status` row against Org B's commit: [6](#0-5) 

### Impact Explanation
Commit status directly drives `Commit#deployable?` and continuous delivery scheduling: [7](#0-6) [8](#0-7) 

and `Status#after_create` callbacks trigger `enable_ci_on_stack` and `schedule_continuous_delivery` on the *target* stack: [9](#0-8) 

An attacker who controls a signed webhook feed for one organization can inject a fabricated `success` status onto a commit belonging to a different, unrelated stack/organization, which can cause an unauthorized/unintended automatic deploy via continuous delivery — this satisfies the "unauthorized deploy" High-impact criterion, since the write crosses the org boundary established at signature-verification time.

### Likelihood Explanation
This requires the attacker to control (or compromise) webhook signing capability for *at least one* organization configured on the Shipit instance (i.e., they must already be able to deliver a validly-signed webhook, which is the normal, intended capability of any org admin who installed the Shipit GitHub App on their org) and to target a `sha` known to also exist in a victim organization's repository history — an unprivileged-attacker path relative to the victim organization, though it depends on cross-repo SHA knowledge/collision, which lowers likelihood somewhat.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository identified in the payload (as `PushHandler` does via `Handler#stacks`/`Repository.from_github_repo_name`) rather than querying `Commit.where(sha: params.sha)` globally, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent, ensuring the authenticated organization/repository matches the commit being mutated.

### Proof of Concept
1. Shipit instance is configured with two GitHub orgs, `org-a` and `org-b`, each with its own `webhook_secret` (per `lib/shipit/github_app.rb` multi-org config).
2. Attacker has legitimate ability to trigger/forge a signed `status` webhook for `org-a` (e.g. is an admin of `org-a`'s installed GitHub App, or intercepts/replays a delivery).
3. Attacker crafts a `status` event payload:
   ```json
   {
     "sha": "<sha known to exist in org-b/victim-repo>",
     "state": "success",
     "context": "ci/travis",
     "repository": { "owner": { "login": "org-a" } }
   }
   ```
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-a")` and validates the HMAC using `org-a`'s `webhook_secret` — signature is valid.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the commit in `org-b`'s repository, and calls `create_status_from_github!`, creating a `success` `Status` on it.
6. `Status#enable_ci_on_stack` and `schedule_continuous_delivery` fire against `org-b`'s stack, potentially triggering an unauthorized deploy there — despite the request never being authenticated against `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
