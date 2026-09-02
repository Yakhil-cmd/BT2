## Title
Team hijack via `github_id`-only lookup in `MembershipHandler#find_or_create_team!` grants unauthenticated org access to privileged `Shipit.github_teams` — (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

## Summary
`find_or_create_team!` resolves a `Team` solely by `params.team.id` (GitHub's numeric team id) and only sets `organization`/`github_team` attributes inside the `find_or_create_by!` block, which Rails skips whenever a matching record already exists. An attacker who owns any GitHub organization onboarded to this Shipit instance (i.e. configured with its own webhook secret via `Shipit.github(organization:)`) can send a fully self-signed `membership` webhook whose `team.id` matches a pre-existing, privileged `Team` row (e.g. one seeded from `Shipit.github_teams`), causing `team.add_member(member)` to add an arbitrary attacker-controlled user to that privileged team without ever validating that `params.organization.login` matches `team.organization`.

## Finding Description
The claimed binding is: `team.organization` (post `find_or_create_team!`) `== params.organization.login` (of the verified webhook). This binding is **not enforced**: [1](#0-0) 

`Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` only assigns `organization` when *creating* a new record. If a `Team` row with that `github_id` already exists (e.g. one of the privileged teams populated via `Shipit.github_teams` / `Team.find_or_create_by_handle`), the block never runs, and the existing row — with its original `organization` — is returned unchanged: [2](#0-1) 

Signature verification is keyed only on `repository_owner`, itself taken straight from the attacker-controlled payload (`repository.owner.login`, falling back to `organization.login`): [3](#0-2) 

Because `Shipit.github(organization: repository_owner)` picks a GitHub App/secret keyed by the organization the attacker names, an attacker who legitimately controls their **own** onboarded org (not in `Shipit.github_teams`) can produce a validly-signed webhook using their own secret while setting every JSON field — including `team.id`, `organization.login`, and `member.login` — to arbitrary values. No part of `ExplicitParameters`, `drop_unhandled_event`, or `verify_signature` cross-checks that the numeric `team.id` genuinely belongs to the organization the signature was verified against.

Exploit flow:
1. Attacker owns org `attacker`, onboarded with its own webhook secret in Shipit.
2. Attacker discovers (via public GitHub API, since team ids/URLs are not secret) the `github_id` of a privileged team, e.g. `shopify/developers` (already a `Team` row because it's listed in `Shipit.github_teams`).
3. Attacker POSTs `X-Github-Event: membership` with body `{ action: 'added', team: { id: <shopify_developers_github_id>, ... }, organization: { login: 'attacker' }, member: { login: 'attacker-user' }, repository: { owner: { login: 'attacker' } } }`, signed with their own valid secret.
4. `verify_signature` passes (org `attacker` is legitimately configured).
5. `find_or_create_team!` finds the existing privileged `Team` by `github_id`, `team.organization` stays `'shopify'`.
6. `team.add_member(member)` adds `attacker-user` into the privileged team.
7. `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) now returns `true` for `attacker-user`, granting them full Shipit access. [4](#0-3) 

## Impact Explanation
This is a cross-tenant authorization escalation: a user never vetted by the real `shopify` GitHub organization is silently inserted into a `Shipit::Team` whose id is enumerated in `Shipit.github_teams`, which is the sole gate used by `force_github_authentication`/`User#authorized?` to grant access to the entire Shipit application. This is repeatable against any team whose `github_id` the attacker can learn (team ids are visible via the GitHub API/UI, not secret), for any tenant organization hosted by the same Shipit instance. This matches the "High — escalation into `Shipit.github_teams` authorization" category.

## Likelihood Explanation
Preconditions: Shipit hosts multiple GitHub organizations (multi-tenant `secrets` config), and the attacker legitimately controls one such onboarded org with its own webhook secret — a normal, low-cost setup for any tenant added to the instance. The attacker needs only the numeric `github_id` of the target team, obtainable via GitHub's public team/org APIs or a rendered team URL. No Shipit credentials, GitHub App private key, or `webhook_secret` of the victim org are required. The attack is a single crafted POST, fully repeatable and scriptable.

## Recommendation
In `find_or_create_team!`, re-validate that the found `Team#organization` matches `params.organization.login` (and ideally that `params.organization.login`/`repository_owner` matches the org whose secret verified the webhook) before performing any mutation such as `add_member`; raise/drop the event on mismatch instead of silently reusing an unrelated team row. Additionally, scope the lookup by both `github_id` and `organization` rather than `github_id` alone.

## Proof of Concept
minitest plan (in `test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test ":membership webhook from a foreign org cannot hijack an existing privileged team" do
  privileged_team = shipit_teams(:shopify_developers) # organization == 'shopify'
  original_org = privileged_team.organization

  @request.headers['X-Github-Event'] = 'membership'
  Shipit.github(organization: 'attacker') # assume configured w/ its own secret
  Shipit.github(organization: 'attacker').stubs(:verify_webhook_signature).returns(true)

  post :create, as: :json, body: {
    action: 'added',
    team: { id: privileged_team.github_id, name: 'x', slug: 'x', url: 'http://x' },
    organization: { login: 'attacker' },
    member: { login: 'attacker-user' },
    repository: { owner: { login: 'attacker' } },
  }.to_json

  assert_response :ok
  assert_equal original_org, privileged_team.reload.organization # binding: expected to hold, but...
  refute_includes privileged_team.members.map(&:login), 'attacker-user' # ...this fails: attacker was added
end
```
The second assertion (`refute_includes`) is expected to fail against current code, demonstrating that `attacker-user` is added as a member of the `shopify`-owned privileged team despite the webhook being signed only for org `attacker`.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
