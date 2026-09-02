### Title
Webhook signature verification is bypassed when no `webhook_secret` is configured, allowing forged `membership` events to escalate an arbitrary GitHub login into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for an organization [1](#0-0) . `WebhooksController#verify_signature` selects which app/secret to check purely from attacker-supplied payload fields (`repository.owner.login` / `organization.login`) [2](#0-1) [3](#0-2) , and when that organization has no `webhook_secret` set, the check passes for any payload regardless of the `X-Hub-Signature` header. This is the same bug class as the reported MemoryGrow issue: the enforcement of a cost/verification step is delegated to a conditional path ("has a `webhook_secret`" / "imports the pay function"), and when that condition is absent, the operation proceeds fully-privileged at effectively zero cost.

### Finding Description
The verification binding that should hold is:
`signature verified over raw_post using org secret == payload is authentically from GitHub for that org`

When `webhook_secret` is `nil`/unset for an organization — a state explicitly supported by the config schema (`webhook_secret: # nil` appears as a valid value in every shipped secrets example: `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`, `test/dummy/config/secrets.test.json`) — `verify_webhook_signature` returns `true` unconditionally: [1](#0-0) 

`WebhooksController#verify_signature` performs no additional authentication; it only logs and calls the handlers: [4](#0-3) 

For the `membership` event, `MembershipHandler#process` trusts the payload completely: it finds-or-creates a local `Team` record keyed by the attacker-controlled `params.team.id`, and adds/removes an arbitrary GitHub login (`params.member.login`) as a member: [5](#0-4) 

`Team.find_or_create_by!(github_id: params.team.id)` matches an *existing* `Team` row if one already exists with that `github_id` — and such a row is exactly what backs `Shipit.github_teams`: [6](#0-5) 

Authorization to log in and use Shipit is gated solely on team membership: [7](#0-6) 

and `User#authorized?` accepts any user who is a member of any team whose id is in `Shipit.github_teams`: [8](#0-7) 

**Before the attack:** verified-sender == GitHub org webhook signer; team membership rows reflect real GitHub team membership fetched via `Team#refresh_members!`/OAuth login.
**After the attack:** any unauthenticated party who knows (a) that the target org has no `webhook_secret` configured and (b) the numeric GitHub team id used in `oauth.teams`, can POST a crafted `membership` payload directly to `/webhooks` and have `MembershipHandler` insert their own GitHub login into that authorized team's `members` association — with zero verified relationship to GitHub at all.

### Impact Explanation
This breaks the "GitHub identity vs. the `User` bound to the session" and "organization authenticated vs. what is written" bindings called out in scope. The result is escalation into `Shipit.github_teams` authorization for an attacker who never authenticated with GitHub and never had a Shipit session — a High-severity unauthenticated authorization bypass. Once in `Shipit.github_teams`, the attacker's subsequent real GitHub OAuth login (or `find_or_create_by_login!`-created record) will pass `authorized?`, granting them the same deploy/rollback/stack-management privileges as legitimate team members.

### Likelihood Explanation
The precondition (`webhook_secret` unset) is not a misconfiguration outside the documented usage — it is the value shown by default/example in every shipped secrets template in this repo, meaning a materially likely number of real deployments run with it unset (e.g., early setup, enterprise/internal-network deployments where operators assume network-level trust). The endpoint `/webhooks` is, by the engine's own design, meant to be internet-reachable (GitHub must be able to POST to it), so no additional access is required beyond knowing the org name and a plausible/guessable team id (numeric GitHub team IDs are often discoverable via the public GitHub API for org teams the attacker can see).

### Recommendation
- Require `webhook_secret` to be present for any organization that has `oauth.teams` configured (fail closed instead of returning `true`), or refuse to boot/serve webhooks for orgs without a secret.
- Do not let unauthenticated webhook payloads mutate `Team#members` for teams referenced by `Shipit.github_teams`; instead, resolve org/team membership by calling back to the GitHub API (as `Team#refresh_members!` already does) rather than trusting the webhook body's `member.login`/`team.id` directly.
- Add fuzz/negative tests that simulate `webhook_secret: nil` combined with forged `membership` payloads to catch this class of bypass in CI.

### Proof of Concept
1. Operator has an org, e.g. `AcmeCorp`, configured in `secrets.yml` with `oauth.teams: ["AcmeCorp/deployers"]` and `webhook_secret` left `nil` (a documented valid value).
2. `Shipit.github_teams` has already created/looked-up a local `Team` row for `AcmeCorp/deployers` with some `github_id` (obtainable via GitHub's public org teams API if the org's teams are visible, or observed from prior legitimate webhook traffic/logs).
3. Attacker, with no Shipit session and no GitHub credentials for the org, sends:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything

{
  "action": "added",
  "team": {"id": <deployers_team_github_id>, "name": "deployers", "slug": "deployers", "url": "https://api.github.com/..."},
  "organization": {"login": "AcmeCorp"},
  "member": {"login": "attacker-github-login"}
}
```
4. `verify_signature` calls `Shipit.github(organization: "AcmeCorp").verify_webhook_signature(...)`, which returns `true` immediately because `webhook_secret` is blank [9](#0-8) .
5. `MembershipHandler#process` runs, finds the existing `Team` by `github_id`, creates/find a `User` for `attacker-github-login`, and adds them as a member [10](#0-9) .
6. When `attacker-github-login` subsequently logs in via GitHub OAuth, `User#authorized?` returns `true` because they are now a member of a team in `Shipit.github_teams` [8](#0-7)  — granting unauthorized access to deploy/rollback stacks.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
