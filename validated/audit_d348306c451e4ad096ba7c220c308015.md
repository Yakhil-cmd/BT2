### Title
Membership webhook authorization bypass allows unauthenticated escalation into `Shipit.github_teams` — ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using an attacker-supplied field from the *unauthenticated* payload itself (`repository.owner.login` / `organization.login`), and `GithubApp#verify_webhook_signature` treats a blank `webhook_secret` as an automatic pass. Combined with the `membership` webhook handler, which trusts the payload to add arbitrary GitHub logins to any `Team` record used for authorization, this breaks the binding "the organization whose credentials were verified" = "the organization whose membership state is written," letting an unprivileged network attacker grant itself membership in a team gating access to the whole Shipit instance.

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the app config to validate against using data taken directly from the unauthenticated JSON body: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that resolved organization: [3](#0-2) 

The setup documentation explicitly marks `webhook_secret` as optional, so multi-organization deployments (and even single-org ones) can legitimately have organizations configured without a secret: [4](#0-3) [5](#0-4) 

Once past this checkpoint, `WebhooksController#create` dispatches the raw, attacker-controlled JSON straight to the registered handler for the event type — no further authentication is performed on the payload contents: [6](#0-5) 

For the `membership` event, `Handlers::MembershipHandler#process` trusts the payload's `team`, `organization`, and `member.login` fields to create/find a `Team` and add or remove a `User` from it: [7](#0-6) 

`Team` records populated this way are exactly the teams referenced by `Shipit.github_teams`, which gate access to the entire application in `Authentication#force_github_authentication`: [8](#0-7) 

**The broken binding:** the organization whose webhook signature was verified (`repository_owner`/`organization.login`, read from the untrusted body) must equal the organization whose `Team`/`Membership` state is mutated by the handler — but if that organization's `webhook_secret` is unset, no signature is checked at all, and the payload's `team`/`member` fields (also untrusted) directly control which user is added to which authorization-gating team.

### Impact Explanation
This is a direct authentication-bypass / escalation into `Shipit.github_teams` authorization, one of the explicitly in-scope High-impact categories: an unauthenticated attacker can add an arbitrary (attacker-controlled) GitHub login to a `Team` used by `Shipit.github_teams`, and then log in via OAuth as that GitHub user to gain full access to the Shipit instance — including triggering deploys, rollbacks, and merges, all of which are otherwise gated by team membership.

### Likelihood Explanation
Likelihood is Medium-to-High wherever an operator configures `Shipit.github` for an organization without a `webhook_secret` — which the documentation and default templates explicitly present as optional/acceptable, so this is a realistic, not merely theoretical, deployment state. No credentials, tokens, or prior access are required; the attacker only needs to know the target organization's slug and POST a crafted JSON body to `/webhooks` with the `membership` event header.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization; refuse to boot / reject all webhooks for organizations without one, rather than silently treating a missing secret as "verified."
- Do not use fields from the unauthenticated request body to select which secret verifies that same body — this is a variant of the classic "algorithm/key confusion" flaw. Or, alternatively require successful signature verification to happen with a secret bound to app configuration only, prior to trusting any parsed field.
- In `MembershipHandler`, cross-check that the `organization.login` in the payload actually matches the GitHub org that authenticated the request (once verification is fixed) before mutating `Team`/`Membership` records.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, where org `victim-org` has `Shipit.github_teams` entries but (per documented "optional" guidance) no `webhook_secret` set for it.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Core", "slug": "core", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-github-user" }
}
```
No `X-Hub-Signature` header is required — `verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank for `victim-org` (`lib/shipit/github_app.rb:76-83`).
3. `MembershipHandler#process` creates/finds the `Team` and calls `team.add_member(User.find_or_create_by_login!("attacker-github-user"))` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-33`).
4. The attacker completes GitHub OAuth as `attacker-github-user`; `Authentication#force_github_authentication` now finds them a member of an authorized team and grants access to the Shipit instance.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
