### Title
Unauthenticated forged GitHub webhook grants `Shipit.github_teams` authorization when `webhook_secret` is unset - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` silently treats an unset `webhook_secret` as "signature verified," so `WebhooksController` accepts and processes arbitrary, unsigned JSON bodies as if they were genuine GitHub webhook deliveries. Combined with `MembershipHandler`, an unauthenticated attacker can forge a `membership` event that adds an arbitrary GitHub login to any `Team`, including a team listed in `Shipit.github_teams`, bypassing the authorization check in `Shipit::Authentication#force_github_authentication`/`User#authorized?` — the same class of bug as the external report: an action (granting authorization / writing state) is performed based on a payload field (`organization`/`team`/`member`) whose integrity is never actually cross-checked against a real signing authority.

### Finding Description
`WebhooksController` runs `verify_signature` as a `before_action`, computing the correct GitHub App per the payload's `repository_owner`/`organization` and delegating signature checking to it: [1](#0-0) [1](#0-0) 

The verification itself is implemented as: [2](#0-1) 

`verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank — i.e. it does not verify the request at all, it merely no-ops. `webhook_secret` is documented and templated as optional/nil in every configuration example shipped with the engine: [3](#0-2) [4](#0-3) 

Because `head(422)` is only called `unless verified` and `verified` is `true` in this state, `create` proceeds to run every registered handler against the caller-supplied JSON body verbatim: [5](#0-4) 

The `membership` handler trusts this body completely, using an attacker-controlled `team`/`organization`/`member` payload to create/find a `Team` and add/remove a `User` from it with no separate verification of GitHub identity: [6](#0-5) [7](#0-6) 

Authorization to use the whole application hinges on team membership derived from exactly this data: [8](#0-7) [9](#0-8) 

**Binding broken:** *"an organization that authenticated"* (the webhook's claimed `organization`/`repository.owner.login`, which is supposed to be cryptographically bound to a GitHub App's `webhook_secret`) *versus "the repository that is written"* — here, versus the `Team`/`Membership` records actually written. When `webhook_secret` is absent, the "authentication" side of that equality is vacuous (`return true unless webhook_secret`), so any caller can claim to be any organization and write team-membership state that Shipit's own authorization gate treats as GitHub-verified truth.

### Impact Explanation
An attacker who knows (or guesses) an existing `github_teams` handle and an existing/creatable GitHub login can add that login to the team via a single unauthenticated POST to `/github/webhooks` (or the engine's mounted webhook path), then log in through the normal GitHub OAuth flow as that user and pass `User#authorized?`. This is a direct escalation into `Shipit.github_teams` authorization — an explicitly listed High-impact category — using no `ApiClient` token, no `webhook_secret`, and no privileged account. It can also be used to desynchronize commit statuses (`status` handler), trigger `GithubSyncJob` (`push` handler), or manipulate review-stack provisioning (`pull_request` handlers), all of which are internally trusted as GitHub-originated.

### Likelihood Explanation
This is exploitable purely by configuration state, not attacker sophistication: `webhook_secret` is `nil`/optional in every shipped example and the app-generation template, so a large fraction of real deployments plausibly run with it unset (mirroring the SKALE report's own reasoning that a config-contingent flaw can still be Medium/High because the "default"/commonly-seen configuration enables it). No secret material, GitHub App private key, or session is required — only network access to the webhook endpoint and knowledge of a target team handle and a target GitHub login (both discoverable from the public UI/GitHub).

### Recommendation
Make `webhook_secret` mandatory for any organization that accepts inbound webhooks; fail closed (`return false`) instead of `return true` when it is unset, and refuse to boot/mount the webhooks route for an org lacking a configured secret. Additionally, avoid trusting a single payload field (`organization`) as both the authentication key selector and the data written; re-validate that the `team`/`organization` in the payload actually belongs to the app configuration used to verify the signature.

### Proof of Concept
1. Deploy Shipit with `config/secrets.yml` using the default/templated `github.webhook_secret: ` (blank), matching `template.rb` and `config/secrets.development.example.yml`.
2. Configure `Shipit.github_teams` to include `acme/developers`.
3. As an unauthenticated attacker, POST to the webhooks endpoint:
```
POST /github/webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": {"id": 999, "name": "developers", "slug": "developers", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "acme"},
  "member": {"login": "attacker-github-login"}
}
```
`verify_signature` calls `Shipit.github(organization: "acme").verify_webhook_signature(nil, body)`, which returns `true` because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
4. `MembershipHandler#process` creates `Team(organization: "acme", slug: "developers")` and adds `User(login: "attacker-github-login")` as a member (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
5. The attacker completes the standard GitHub OAuth login flow as `attacker-github-login`; `User#authorized?` now returns `true` because the user belongs to a `Shipit.github_teams` team, granting full application access without ever having real GitHub organization membership.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-12)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
```

**File:** template.rb (L61-74)
```ruby
%w(config/secrets.yml config/secrets.example.yml).each do |path|
  create_file path, <<~CODE, force: true
    development:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
      host: 'http://localhost:3000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-34)
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
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
