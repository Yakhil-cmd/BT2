### Title
Webhook signature verification silently accepts unsigned/forged requests when `webhook_secret` is unset, breaking the "authenticated organization = repository being written" binding - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the organization resolved from the (unauthenticated) payload. Since the setup docs present `webhook_secret` as *optional*, any Shipit deployment following the documented setup without setting it will accept **arbitrary, unsigned POST requests** to `/webhooks` and treat them as authentic GitHub events, driving privileged side effects (team membership changes, commit statuses that gate continuous deployment) without any credential, session, or `ApiClient` token.

### Finding Description
`WebhooksController#verify_signature` determines which `GitHubApp` instance to use for verification purely from the attacker-controlled JSON body, then defers all trust to that instance's HMAC check: [1](#0-0) 

The `repository_owner` used to pick the app config comes straight from the unverified payload: [2](#0-1) 

The actual verification method contains the break in the binding: [3](#0-2) 

`return true unless webhook_secret` means that for any organization configured without a `webhook_secret` (explicitly called out as **optional** in the setup guide), `verify_webhook_signature` passes regardless of whether a signature header is even present. The controller then dispatches the entire unauthenticated payload to registered handlers: [4](#0-3) 

The equality that should hold is: `organization whose secret was verified == organization on whose behalf commit/team state is mutated`. When `webhook_secret` is blank, the left side of that equation is never actually checked — it degenerates to "any anonymous sender," while the right side (state mutations against real Stacks/Teams/Users) still executes fully.

Concrete impact paths reachable from this same, single missing check:
- `MembershipHandler#process` trusts `params.team`/`params.member`/`params.organization` outright to create/delete `Team` and `Membership` records: [5](#0-4) 
  Team membership is exactly what gates authorization in `User#authorized?` and the `force_github_authentication` check that decides whether a session's `current_user` may use the whole app: [6](#0-5) [7](#0-6) 
- `StatusHandler#process` writes a `Status` for any commit matching an attacker-chosen `sha`: [8](#0-7) 
  A forged `success` status flips `Commit#state`, which is exactly the trigger `Status#schedule_continuous_delivery` uses to kick off automatic deployment for stacks with `continuous_deployment: true`: [9](#0-8) [10](#0-9) 

### Impact Explanation
This maps to two of the accepted High-impact categories: escalation into `Shipit.github_teams` authorization (via forged `membership` events that add an attacker-controlled GitHub login to a team on `Shipit.github_teams`, letting an anonymous internet caller pass `force_github_authentication` and `authorized?` once they also complete normal GitHub OAuth as that login), and an unauthorized deploy (via forged `status` events flipping a commit's CI state to `success`, which `ProcessMergeRequestsJob`/continuous-delivery scheduling then acts on to trigger a real deploy). Both require zero credentials, no `ApiClient` token, no `webhook_secret`, and no repository write access — only that the target Shipit instance was set up per the documented, "optional" `webhook_secret` guidance.

### Likelihood Explanation
The setup documentation explicitly frames `webhook_secret` as optional (`docs/setup.md` line "Webhook secret (optional)"), so this is not a contrived misconfiguration — it is the state a naive-but-documentation-following install ends up in. Any operator who skips this optional field silently disables all webhook authentication, and the vulnerability requires nothing beyond `curl`ing `/webhooks` with a crafted JSON body and the appropriate `X-Github-Event` header.

### Recommendation
Do not treat a missing `webhook_secret` as "verification succeeds." Instead, either (a) require `webhook_secret` to be present for every configured GitHub organization at boot/validation time, refusing to serve `/webhooks` otherwise, or (b) fail closed (`return false`) when `webhook_secret` is blank, so unsigned requests are rejected by default rather than accepted by default.

### Proof of Concept
1. Configure Shipit per the documented example, leaving `github.<org>.webhook_secret` blank (as the setup guide marks it optional).
2. Send, without any signature header:
```
POST /webhooks HTTP/1.1
X-Github-Event: membership
Content-Type: application/json

{"action":"added","team":{"id":1,"name":"Developers","slug":"developers","url":"https://example.com"},
 "organization":{"login":"<configured-org>"},"member":{"login":"attacker-github-login"}}
```
`verify_signature` calls `Shipit.github(organization: "<configured-org>").verify_webhook_signature(nil, raw_body)`, which returns `true` at `lib/shipit/github_app.rb:77` because `webhook_secret` is blank. `MembershipHandler#process` then creates the team (if needed) and adds `attacker-github-login` as a member, all without the attacker ever authenticating to Shipit or GitHub for that organization.
3. Separately, POST an unsigned `status` event with `sha` of a real tracked commit and `state: "success"` to force `Commit#state` to `success` on a stack with `continuous_deployment: true`, triggering an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
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

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
