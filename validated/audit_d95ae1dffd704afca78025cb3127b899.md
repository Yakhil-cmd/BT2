### Title
Unauthenticated cross-repository webhook forgery via organization/repository binding confusion — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret used to authenticate an inbound GitHub webhook from a field inside the **unauthenticated request body itself** (`repository.owner.login` / `organization.login`), while the resource that is actually mutated by the event handlers is selected from a **different, independently-controlled field** (`repository.full_name`, or bare `sha`/`team`/`member` values). This breaks the intended binding `organization that authenticated == repository/resource that is written`. When any one GitHub organization configured on the instance has no `webhook_secret` set (an explicitly optional, documented configuration), an unauthenticated attacker can pick that organization to trivially pass signature verification and then forge event payloads targeting any other tracked repository, commit, or team.

### Finding Description
`Shipit::WebhooksController` is public/unauthenticated (`ActionController::Base`, no `Shipit::Authentication` concern) and dispatches events based purely on parsed JSON: [1](#0-0) 

Signature verification selects the `GitHubApp`/secret using `repository_owner`, which is read straight out of the untrusted, unauthenticated JSON body: [2](#0-1) 

`verify_webhook_signature` returns `true` unconditionally whenever the selected organization has no `webhook_secret` configured: [3](#0-2) 

The webhook secret is documented as **optional** per organization/app: [4](#0-3) 

Once verification is (trivially) satisfied for the attacker-chosen `repository.owner.login`, the actual resource acted upon is derived from unrelated fields that are never required to match the organization used for verification:

- `StatusHandler` writes a `Status` for **any** commit matching `sha` globally, with no scoping to the verified organization/repository: [5](#0-4) 
- `Handler#repository_name` / `Handler#stacks` resolve the target repository from `payload.dig('repository','full_name')`, independent of the value used for signature selection: [6](#0-5) 
- `MembershipHandler` adds/removes an arbitrary GitHub login to/from a `Team` purely from JSON fields, with no re-verification against GitHub: [7](#0-6) 

Committing a forged `success` status changes commit state and can trigger merge-queue scheduling: [8](#0-7) 

And `Shipit.github_teams` (via `Team`/`Membership`) directly gates authorization to the whole application: [9](#0-8) 

### Impact Explanation
This is the same bug class as the referenced report: an unauthenticated, attacker-controlled field is trusted to select a security-relevant target/credential (there: outbound `Host`; here: which organization's secret gates the request) while the field that determines what actually gets acted on is a separate, unchecked value. The exploitable consequence in Shipit is not SSRF but an **unauthenticated forged webhook** whose blast radius is decoupled from the (weak) authentication check performed:
- Forge CI status (`success`/`failure`) on arbitrary commits tracked by the instance, potentially unblocking an unauthorized deploy/merge via `stack.schedule_merges`.
- Forge `membership added` events to insert an arbitrary GitHub login into a `Team` that backs `Shipit.github_teams`, escalating into application authorization.
- Forge `pull_request`/`check_suite` events to provision, archive/unarchive review stacks belonging to repositories unrelated to the organization used to pass the (secret-less) check.

This lands in the in-scope "High" bucket: escalation into `Shipit.github_teams` authorization and cross-repository writes/unauthorized deploy triggers.

### Likelihood Explanation
Exploitability hinges on at least one configured GitHub organization/app lacking a `webhook_secret` — an explicitly optional setting per the engine's own setup documentation, not a deviation from documented deployment. Any installation using the single-org config without a webhook secret configured, or a multi-org config where at least one org omits it, is exposed to fully unauthenticated forgery against every *other* tracked repository. No GitHub write access, `ApiClient` token, session, or `webhook_secret` knowledge is required.

### Recommendation
- Reject events where `repository_owner`/`organization.login` used for signature selection does not match the `repository.full_name` / team `organization` actually acted upon by the handler.
- Do not allow `verify_webhook_signature` to silently pass (`return true`) when `webhook_secret` is blank; instead require an explicit, instance-wide opt-in (e.g., `Shipit.authentication_disabled?`-style flag) and log/alert loudly, or reject the request.
- Scope `StatusHandler`'s `Commit.where(sha: ...)` lookup to the repository named in the (verified) payload rather than matching by `sha` alone across the whole instance.

### Proof of Concept
1. Configure Shipit with multiple GitHub organizations (`docs/setup.md` "Using Multiple Github Applications"), where org `attacker-org` is installed with no `webhook_secret`, and org `victim-org` (with `victim-org/repo` tracked and a stack configured) has a secret set.
2. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature`, body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/repo" },
  "sha": "<known-sha-of-victim-commit>",
  "state": "success",
  "context": "required-check"
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(...)`, which returns `true` immediately because `attacker-org` has no `webhook_secret`.
4. `StatusHandler#process` creates a `success` `Status` on the commit matching `sha`, regardless of the fact that this commit belongs to `victim-org/repo`, which was authenticated by no secret at all — potentially unblocking a merge/deploy for a repository the attacker never authenticated against.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
