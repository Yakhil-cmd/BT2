### Title
Webhook signature verification is silently bypassed when an organization's `webhook_secret` is unset, enabling forged `membership` events that escalate a GitHub identity into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::GithubApp#verify_webhook_signature` unconditionally treats an unset `webhook_secret` as "verified", exactly mirroring the POSU-1 bug class: a first check that becomes moot when a security parameter (`MIN_COLLATERAL_USD` there, `webhook_secret` here) is not configured. In `shipit-engine`, `WebhooksController#verify_signature` uses this method as the sole authentication gate for the unauthenticated `/webhooks` endpoint. When any onboarded GitHub organization is configured without a `webhook_secret`, an unprivileged remote attacker can POST arbitrary, unsigned JSON to that endpoint and have it processed as if it came from GitHub, including the `membership` handler, which creates `Team`/`User`/`Membership` records that directly feed `User#authorized?` and thus `Shipit.github_teams` authorization.

### Finding Description
The webhook signature check is: [1](#0-0) 

`return true unless webhook_secret` means verification is entirely skipped — not merely weakened — whenever the organization's config omits `webhook_secret`. This is invoked from the only authentication gate on the webhook ingress point: [2](#0-1) 

The controller picks which organization's app/secret to check based on a field read out of the attacker-supplied payload itself (`repository_owner`), and if that organization's `webhook_secret` is blank, `verified` is `true` for any payload/signature combination — including a request with no `X-Hub-Signature` header at all. The request then flows unauthenticated into the handler dispatch: [3](#0-2) 

One of the default handlers is `MembershipHandler`, which creates/updates `Team` and `User` records and adds/removes `Membership` rows purely from payload content, with no cross-check against real GitHub state: [4](#0-3) 

Those `Membership`/`Team` records are exactly what backs the authorization decision in `User#authorized?`, which is the check enforced on every authenticated request via `force_github_authentication`: [5](#0-4) [6](#0-5) 

**Binding broken:** *organization authenticated (via webhook signature) ≠ organization/records actually written by the handler that processes the request.* Before the attacker's request: `verified == (valid HMAC over raw body)`. After: for an org with no configured `webhook_secret`, `verified == true` unconditionally, so the "authenticated organization" side of the binding is vacuous while the "records written" side (arbitrary `Team`/`User`/`Membership` rows tied to any GitHub login string the attacker names) is fully attacker-controlled.

### Impact Explanation
This crosses the "High" bar explicitly allowed by scope: *escalation into `Shipit.github_teams` authorization*. An attacker who can identify (or brute-force via trial payloads) an organization onboarded to this Shipit instance without a configured `webhook_secret` can:
1. POST a forged `membership` webhook naming an arbitrary GitHub `login` (potentially the attacker's own GitHub account) and a `team` whose `id`/`slug` corresponds to a team configured in `Shipit.github_teams`.
2. `MembershipHandler#process` creates the `User` via `User.find_or_create_by_login!`, creates/finds the `Team`, and calls `team.add_member(member)`.
3. On the attacker's next real OAuth login, `current_user.authorized?` finds the now-existing `Membership` row and grants access to the application, bypassing the intended "must belong to a permitted GitHub team" gate — without ever having been added to that team on GitHub itself.

No `webhook_secret`, `ApiClient` token, session, or repository write access is required — only knowledge that an onboarded org has this field unset, which is a valid (if insecure) configuration state of the engine's own code, not a deviation from documented mounting.

### Likelihood Explanation
Likelihood depends entirely on whether any organization configured in the host's `Shipit.github` config omits `webhook_secret`. The engine's own code does not enforce that this field be present — `verify_webhook_signature` is written to accept its absence as valid — so this is a first-class supported configuration path in the engine, not a misconfiguration that requires deviating from documented deployment. Given webhook endpoints are unauthenticated by design (`skip_before_action :verify_authenticity_token`) and the org selection itself is payload-derived, exploitation requires only sending an HTTP POST with a crafted JSON body.

### Recommendation
Treat a missing `webhook_secret` as a hard authentication failure rather than an implicit pass:
```ruby
def verify_webhook_signature(signature, message)
  return false if webhook_secret.blank?
  return false if signature.blank?

  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'

  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
```
Additionally, require `webhook_secret` presence at config-load time (fail fast) so operators cannot silently disable webhook authentication, mirroring the recommended "add zero/nil checks" fix from POSU-1.

### Proof of Concept
1. Configure (or identify) an organization in `Shipit.github` without a `webhook_secret`.
2. Send, without any `X-Hub-Signature` header:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_signature` computes `verified = true` because `webhook_secret` is blank, so the request passes straight through to `MembershipHandler`, which creates the `Team`, creates/finds the `User` for `attacker-github-login`, and inserts a `Membership` row.
4. If `deployers` corresponds to a team configured in `Shipit.github_teams`, the attacker's real GitHub account, once OAuth-authenticated, passes `User#authorized?` and gains access to the Shipit instance.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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
