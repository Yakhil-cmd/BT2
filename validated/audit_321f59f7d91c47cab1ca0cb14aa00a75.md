### Title
Webhook authentication is silently disabled per-organization, letting an unauthenticated actor forge team-membership events and self-grant `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The referral bug's root cause is a missing equality check: the value the code *trusts* (referrer) is never bound to the value that was actually *authorized*. The same class of gap exists in Shipit's webhook trust model: the "organization" whose credential is used to authenticate a webhook is not reliably bound to a real, verified secret, and the resulting event is trusted to mutate authorization-relevant state (`Team`/`Membership`) regardless.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/secret to validate against using an attacker-supplied field of the same unauthenticated payload: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the JSON body (`repository.owner.login`, falling back to `organization.login`) *before* any cryptographic check has happened, and that value in turn selects which `GitHubApp` instance (and therefore which `webhook_secret`) is used to verify the signature.

The verification itself is a documented no-op when an organization has no configured secret: [3](#0-2) 

`return true unless webhook_secret` means any organization entry in a multi-org Shipit config that omits `webhook_secret` (a supported configuration shape, shown as `webhook_secret: # nil` for every org) accepts **any** payload as authentic: [4](#0-3) 

Because the "authenticated organization" is derived from attacker-controlled JSON and is only as strong as that organization's *own* (possibly absent) secret, an attacker who knows (or guesses) that one configured organization has no `webhook_secret` can send a `membership` event naming that organization and have it processed with full trust - even though no GitHub signature was ever verified. `MembershipHandler` then unconditionally mutates authorization state from that untrusted payload: [5](#0-4) 

`params.member.login` is used to `find_or_create_by_login!` an arbitrary GitHub login and add it to `team.add_member(member)` for a `Team` keyed by an attacker-chosen `github_id`/`organization`. Interactive session authorization (`Authentication#force_github_authentication`) subsequently trusts these locally-stored `Team`/`Membership` rows, not a live GitHub check, to decide whether `current_user.authorized?` for `Shipit.github_teams`: [6](#0-5) 

The binding that should hold - "the GitHub organization that cryptographically authenticated the webhook" == "the organization whose team membership state is mutated and later trusted for authorization" - is never enforced: verification can be a no-op for one org while `Shipit.github_teams` authorization decisions are made engine-wide from the `Team`/`Membership` tables that any organization's (even secret-less) webhook can write to.

### Impact Explanation
This lets an unprivileged network attacker forge team membership for any GitHub login into any team Shipit knows about, which is then consumed by `Authentication#force_github_authentication` to authorize sessions - i.e. escalation into `Shipit.github_teams` authorization, one of the accepted High-severity impacts. It can grant an otherwise-unauthorized GitHub account full access to the Shipit UI/console for stacks, deploys, and rollbacks.

### Likelihood Explanation
Requires (a) a multi-organization Shipit deployment where at least one configured organization has no `webhook_secret` (an explicitly supported, documented configuration shape) and (b) the attacker being able to reach the public `/webhooks` endpoint, which is unauthenticated by design. No GitHub credentials, `ApiClient` token, or webhook secret possession is needed - the attacker is exploiting the *absence* of the secret rather than needing to know one, so it does not fall under the "requires a webhook_secret" exclusion. Likelihood depends on operator configuration (a secret-less org existing alongside protected orgs), which I could not verify is disallowed anywhere else in the engine's validation code from what was indexed.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization in production (fail configuration validation if any org is missing one), removing the `return true unless webhook_secret` bypass in `lib/shipit/github_app.rb`.
- Do not derive the "authenticating organization" from unauthenticated payload fields before verification; instead verify against every configured secret (or a per-app-installation key) and reject if none matches.
- In `MembershipHandler`/`Handler`, cross-check that the organization used to select the verifying secret matches the organization whose `Team`/`Membership` state is being mutated.

### Proof of Concept
Conceptual sequence (not executable without a target deployment matching the config precondition):
1. Configure/observe a multi-org Shipit instance where org `no-secret-org` has `webhook_secret: nil` while org `victim-org` has team `victim-org/admins` listed in `Shipit.github_teams`.
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 1, "name": "admins", "slug": "admins", "url": "https://x"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-github-login"}
}
```
No valid `X-Hub-Signature` is required because `Shipit.github(organization: "victim-org")` will pass verification if `victim-org`'s secret is unset, or the attacker targets whichever configured org lacks a secret while naming any `Shipit.github_teams` team in `organization.login`/`team`.
3. `MembershipHandler#process` creates/finds `Team` and adds `attacker-github-login` as a member via `team.add_member(member)` [7](#0-6) .
4. Attacker logs in via GitHub OAuth with that login; `current_user.authorized?` now succeeds because Shipit's local `Membership` table (not live GitHub state) says so [8](#0-7) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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
