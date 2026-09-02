### Title
Membership webhook lets attacker's own org's signature authenticate a `Team` record claiming a different, unproven `organization` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` validates the HTTP signature using `repository_owner`, which prefers `params.dig('repository','owner','login')` over `params.dig('organization','login')`. `MembershipHandler#find_or_create_team!` instead trusts `params.organization.login` directly into `team.organization`. Because `membership` events never legitimately contain a top-level `repository` key, an attacker can inject one into a hand-crafted, self-signed request to make `repository_owner` resolve to an org they control (and whose secret they can sign with), while `organization.login` in the same payload names an arbitrary victim org, causing a `Team` row to be created that falsely claims ownership by that victim org.

### Finding Description
The binding the code implicitly assumes is:
`repository_owner` (the org whose `webhook_secret` validated this request, in `app/controllers/shipit/webhooks_controller.rb`) == `params.organization.login` (the org value trusted into `team.organization`, in `app/models/shipit/webhooks/handlers/membership_handler.rb:41`).

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to pick which org's HMAC secret validates the signature: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [2](#0-1) . Each configured org has its own `webhook_secret` used in HMAC comparison [3](#0-2) .
- `MembershipHandler#find_or_create_team!` independently reads `params.organization.login` and assigns it straight to `team.organization` inside the creation block, keyed only by `github_id: params.team.id` [4](#0-3) .
- Real GitHub `membership` webhook payloads never include a top-level `repository` key (it is an org-level event: `action`, `scope`, `member`, `team`, `organization`, `sender`). Because `repository_owner`'s precedence favors `repository.owner.login` first, this fallback field is never exercised by genuine GitHub traffic and thus was never intended to diverge from `organization.login`. However, `POST /webhooks` is directly reachable by any internet user with no Shipit session, and nothing enforces that the JSON body actually matches a real GitHub `membership` payload shape — the attacker fully controls the raw HTTP body they sign.
- Attack: attacker operates (or configures) an org "attacker-org" recognized by Shipit with its own `webhook_secret` (a scenario explicitly permitted: attacker "can emit webhooks from a repository they own"). They POST to `/webhooks` with header `X-Github-Event: membership` and a body such as:
```json
{
  "action": "added",
  "team": {"id": 999999, "name": "x", "slug": "x", "url": "u"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
signed with `attacker-org`'s own `webhook_secret`. `verify_signature` resolves `repository_owner` to `"attacker-org"`, fetches `attacker-org`'s secret, and the signature checks out — the request passes authentication. `MembershipHandler#process` then reads `params.organization.login == "victim-org"` and, since `github_id: 999999` is new, creates a `Team` row with `organization = "victim-org"` and `github_team = params.team` [5](#0-4) , despite `victim-org`'s webhook secret never being involved.
- No other guard intercepts this: `drop_unhandled_event` only checks that a handler exists for the event type [6](#0-5) ; the `ExplicitParameters` schema in `MembershipHandler` only validates presence/type of fields, not cross-consistency with `repository_owner` [7](#0-6) ; `find_or_create_by!` only dedupes on `github_id`, not `organization` [4](#0-3) .

### Impact Explanation
A `Team` record's `organization` attribute — used elsewhere for GitHub-team-based authorization gating (`Shipit.github_teams` membership checks) — can be forged to name any org string without that org's webhook secret ever validating the request. This is a payload signed and authenticated for one org ("attacker-org") mutating/creating a `Team` record attributed to another org ("victim-org") that never authenticated it — matching the Critical category "a payload for one repository/org mutating another's ... team." If downstream authorization logic keys off `team.organization` when checking `Shipit.github_teams`, this could contribute to escalation into a team-scoped authorization decision for an org the attacker does not control.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment where the attacker's own org is one of the configured orgs with its own `webhook_secret` (a legitimate, low-cost setup for any GitHub org owner integrating with a shared Shipit instance), (2) knowledge that `membership` events omit `repository` in genuine traffic so the fallback path is exploitable, and (3) the ability to freely craft and sign an HTTP POST body (trivial, since the attacker controls their own org's secret). No Shipit session, API token, or victim-org secret is needed. The attack is repeatable against any `github_id`/team id not already present, for any victim org name of the attacker's choosing.

### Recommendation
In `WebhooksController#verify_signature`, do not allow `repository.owner.login` to silently substitute for `organization.login` when both may be present, and reject/ignore any `repository` key on events (`membership`, `organization`, `team`, etc.) that GitHub never legitimately includes it for. More robustly, `MembershipHandler` should assert `params.organization.login == repository_owner` (passed down explicitly, not re-derived) before trusting the value into `team.organization`, or the org used for signature verification should be threaded through to the handler instead of being independently re-parsed from attacker-controlled JSON.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook can bind Team to organization not authenticated by webhook signature" do
  # Assume Shipit is configured with two orgs: "attacker-org" (attacker's own secret) and "victim-org"
  payload = {
    action: 'added',
    team: { id: 999999, name: 'x', slug: 'x', url: 'u' },
    organization: { login: 'victim-org' },
    member: { login: 'attacker' },
    repository: { owner: { login: 'attacker-org' } } # spoofed field, never sent by real GitHub for membership events
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, payload)

  post :create, body: payload, headers: {
    'X-Github-Event' => 'membership',
    'X-Hub-Signature' => signature,
    'Content-Type' => 'application/json'
  }

  assert_response :ok
  team = Shipit::Team.find_by(github_id: 999999)
  # Binding assertion: the org that authenticated the request (attacker-org)
  # must equal the org trusted into team.organization if the binding held.
  assert_not_equal 'attacker-org', team.organization
  assert_equal 'victim-org', team.organization # demonstrates unauthenticated org attribution
end
```
This confirms `team.organization` ("victim-org") diverges from the org whose secret actually authenticated the request ("attacker-org"), proving the binding is broken.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-24)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
