### Title
Unauthenticated Membership-Webhook Processing When No `webhook_secret` Is Configured Allows Escalation into `Shipit.github_teams` Authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::WebhooksController` gates all inbound webhook processing on a single check, `verify_signature`, which delegates to `GitHubApp#verify_webhook_signature`. That method contains an explicit bypass: `return true unless webhook_secret`. Because `webhook_secret` is documented as an *optional* per-organization setting, any Shipit deployment (or any single organization in a multi-org config) that omits it will accept **unsigned, unauthenticated** webhook POSTs from anyone on the internet and dispatch them straight into event handlers — including `MembershipHandler`, which mutates `Shipit::Team` membership, the exact table that backs `User#authorized?` / `Shipit.github_teams` access control.

### Finding Description
`WebhooksController#verify_signature` resolves the organization from the payload and asks that organization's `GitHubApp` instance to validate the HMAC signature: [1](#0-0) 

The verification itself is: [2](#0-1) 

`webhook_secret` is only set if the organization's config supplies one (`@webhook_secret = @config[:webhook_secret].presence`), and the setup documentation explicitly calls it optional: [3](#0-2) 

When `webhook_secret` is absent, `verify_webhook_signature` returns `true` unconditionally — no signature is checked at all, yet `WebhooksController#create` still dispatches the raw, attacker-controlled JSON body to every registered handler for the claimed event type: [4](#0-3) 

The `membership` event is one of these handlers, and it directly creates/attaches `Shipit::Team` and `Shipit::Membership` records based purely on payload content — no cross-check against any authenticated identity: [5](#0-4) 

`Shipit::Team` is the same model referenced by `Shipit.github_teams`, and `User#authorized?` grants access to the whole application based solely on membership in one of those teams: [6](#0-5) 

`RepositoriesController` (and other UI controllers) enforce that a logged-in GitHub user must belong to one of `Shipit.github_teams` before they can see or act on any repository: [7](#0-6) 

**The broken binding:** the signature check is meant to guarantee `organization that authenticated == source of the event being trusted`, but when no secret is configured that equality collapses to `true == true` unconditionally — the "authenticated organization" side of the equation is never actually verified, while the "team membership written" side of the equation (which directly controls `Shipit.github_teams` authorization) is fully attacker-controlled.

### Impact Explanation
An unauthenticated remote attacker who knows (a) the numeric GitHub team `id` and organization `login` of a team listed in `Shipit.github_teams` (both are visible/guessable via the GitHub org's public team page or API) and (b) their own real GitHub login, can POST a forged `membership` webhook (`action: 'added'`) to `/webhooks` on any Shipit deployment where that organization has no `webhook_secret` configured. This adds the attacker's `Shipit::User` (auto-vivified via `User.find_or_create_by_login!`) to the matching `Shipit::Team`. After that, a normal GitHub OAuth login (an ordinary, unprivileged flow) will satisfy `authorized?`, granting the attacker full access to Shipit's UI/API for that install — viewing stacks, triggering deploys/rollbacks/tasks, and merging PRs. This falls squarely under the "escalation into `Shipit.github_teams` authorization" and "unauthorized deploy/rollback/merge" impact categories.

### Likelihood Explanation
The precondition (`webhook_secret` unset for the relevant organization) is a normal, documented configuration state, not a misconfiguration that violates the setup guide — the guide explicitly marks the field optional. Any operator who skips it (e.g., during initial setup, or in a multi-org config where a secondary org's secret was forgotten, as shown by the `OrgTwo` fixture with `webhook_secret: # nil`) is silently exposed. No credentials, tokens, or repository access are required by the attacker — only network reachability to `/webhooks` and public knowledge of a team id/org/slug/url.

### Recommendation
Do not treat an absent `webhook_secret` as "skip verification." Require and enforce a `webhook_secret` for every configured GitHub organization (fail closed, e.g., reject at boot or return `422`/`401` for that org's webhooks), or at minimum require a secret specifically for privileged events such as `membership` before they are allowed to mutate `Team`/`Membership` records that feed into `Shipit.github_teams` authorization.

### Proof of Concept
1. Configure Shipit with an organization whose `github` config omits `webhook_secret` (a supported/documented configuration, see `docs/setup.md` and the `OrgTwo` fixture in `test/dummy/config/secrets_double_github_app.yml`).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature`, body:
```json
{
  "action": "added",
  "organization": { "login": "target-org" },
  "team": { "id": 123, "name": "Deployers", "slug": "deployers", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_signature` calls `verify_webhook_signature(nil, body)` → `webhook_secret` is blank → returns `true` → request proceeds.
4. `MembershipHandler#process` creates/finds `Team` `id: 123` and adds `attacker-github-login` as a member.
5. Attacker logs into Shipit via the normal GitHub OAuth flow; if team `123` is listed in `Shipit.github_teams`, `current_user.authorized?` now returns `true`, granting full application access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** test/controllers/repositories_controller_test.rb (L19-28)
```ruby
    test "current_user must be a member of at least a Shipit.github_teams" do
      session[:user_id] = shipit_users(:bob).id
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks), shipit_teams(:shopify_developers)])
      get :index
      assert_response :forbidden
      assert_equal(
        'You must be a member of cyclimse/cooks or shopify/developers to access this application.',
        response.body
      )
    end
```
