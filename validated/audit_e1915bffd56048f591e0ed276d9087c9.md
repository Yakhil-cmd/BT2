Found it: the `MembershipHandler` accepts a webhook `team.id`/`organization.login`/`member.login` and mutates `Shipit.github_teams` membership, but the identity that GitHub verifies the webhook signature for (`repository_owner`/`organization` used to look up which `github_app.webhook_secret` to check against) is derived from the same untrusted JSON body it later uses to add members to a team, so any GitHub organization whose Shipit-configured `webhook_secret` is blank bypasses verification entirely and lets an unauthenticated caller add themselves to any `Shipit.github_teams`-authorizing team.

### Title
Unauthenticated webhook signature bypass allows spoofed `membership` events to grant `Shipit.github_teams` authorization - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config to validate a signature against using an untrusted field taken directly from the request body (`repository.owner.login` / `organization.login`), and then delegates the actual "is this authentic" decision to `GithubApp#verify_webhook_signature`, which returns `true` (verified) whenever no `webhook_secret` is configured for that organization. This breaks the binding: *the organization Shipit believes authenticated the request* must equal *the organization/team whose membership is written* by `MembershipHandler`. If any organization known to this Shipit install has no `webhook_secret` configured, an attacker with no credentials at all can forge a `membership` webhook event claiming that organization, and `MembershipHandler#process` will happily add an attacker-controlled GitHub login to a `Team`, which is used by `User#authorized?` to gate access via `Shipit.github_teams`.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` computes the org used for verification purely from the payload: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` short-circuits to `true` (verified) if that organization's config has no `webhook_secret`: [3](#0-2) 

Once "verified", `WebhooksController#create` dispatches the raw, attacker-controlled JSON straight to handlers: [4](#0-3) 

`MembershipHandler#process` trusts `params.team`, `params.organization`, and `params.member.login` verbatim to create/find a `Team` and add/remove a `User` as a member: [5](#0-4) 

That `Team` membership is exactly what gates application access: `User#authorized?` checks `teams.where(id: Shipit.github_teams...)`, and `Shipit::Authentication#force_github_authentication` enforces it before granting access to the whole app: [6](#0-5) [7](#0-6) 

So the binding that should hold is: `organization whose secret validated the webhook == organization/team the webhook is permitted to mutate`. Because `verify_webhook_signature` treats "no secret configured" as "verified", and the org used to pick the (missing) secret is attacker-supplied, this binding is not enforced for any org lacking a configured `webhook_secret`. This is directly analogous to the `BitVMBridge.mint` bug: a privileged action (minting / granting `Shipit.github_teams` authorization) is performed using a recipient/target field (`to` address / GitHub org+team+member) that is never actually tied to the thing that was supposedly verified (the BTC tx / the HMAC signature).

### Impact Explanation
This allows an unauthenticated network attacker to forge a `membership` (or `push`, `status`, `check_suite`, etc.) webhook event and have Shipit act on it as if GitHub sent it, for any organization that has no `webhook_secret` configured (the setup docs list the webhook secret as "optional"). Concretely via `membership`, an attacker can add any arbitrary GitHub login (including their own) to a `Team` that is part of `Shipit.github_teams`, thereby escalating into `Shipit.github_teams` authorization and gaining access to the whole Shipit UI/API for that install — this matches the explicitly-listed High-severity impact "escalation into `Shipit.github_teams` authorization." Depending on which teams are used to authorize deploy permissions, this can cascade into unauthorized deploys.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it only manifests for GitHub organizations configured in `Shipit.github_apps`/`config/secrets.yml` without a `webhook_secret`. Because the setup guide explicitly marks the webhook secret as optional, this is a realistic misconfiguration, not a purely theoretical one, and requires no credentials, session, or API token from the attacker — only network access to `/webhooks` and knowledge of the target organization's login and a target team id (discoverable via the Shipit UI, which is otherwise unauthenticated for this attack).

### Recommendation
Do not treat "no `webhook_secret` configured" as an automatic pass in `GithubApp#verify_webhook_signature`; require a configured secret before accepting any webhook for an organization, or fail closed with a clear misconfiguration error rather than silently trusting the payload. Also validate that the organization derived for signature lookup is the same organization actually mutated by the handler (defense in depth), and update `docs/setup.md` to mark `webhook_secret` as mandatory rather than optional.

### Proof of Concept
1. Deploy Shipit with `Shipit.github_apps` containing an organization entry `evilorg` (or any org known to Shipit) with `webhook_secret` unset/blank, while `Shipit.github_teams` includes a team belonging to `evilorg`.
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature`, with a JSON body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Admins", "slug": "admins", "url": "https://github.com/x" },
  "organization": { "login": "evilorg" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_signature` looks up `Shipit.github(organization: "evilorg")`, finds no `webhook_secret`, and `verify_webhook_signature` returns `true` unconditionally, per [3](#0-2) .
4. `MembershipHandler#process` runs, creating/joining `attacker-github-login` to team id `999`, per [8](#0-7) .
5. Attacker logs into Shipit via normal GitHub OAuth as `attacker-github-login`; `User#authorized?` now returns `true` because of the forged team membership, granting full application access per `Shipit::Authentication#force_github_authentication`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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
