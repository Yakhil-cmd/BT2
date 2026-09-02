### Title
Cross-org forged `membership` webhook can delete an operator's `Membership` row via `github_id`-only team lookup - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` solely by `params.team.id` (GitHub's numeric team ID), never verifying that `params.organization.login` matches the team's actual `organization`. An attacker who administers any organization that Shipit already trusts (has a configured `GithubHook::Organization` webhook secret) can send a genuinely-signed `membership` webhook naming their own org, but with a `team.id` belonging to a different org's team in `Shipit.github_teams`, and a `member.login` of a real operator, causing `team.members.delete(member)` to remove that operator's `Membership`.

### Finding Description
The broken binding: a `Membership` row for `team` (where `team ∈ Shipit.github_teams`) should equal `team.organization`'s own GitHub-reported membership state — i.e. `Membership.exists?(team:, user:) == github.org(team.organization).team_members.include?(user)`. This is violated because `find_or_create_team!` does: [1](#0-0) 

which looks the `Team` up by `github_id` alone, with no `organization` filter, and only assigns `organization` when the record does not already exist. If a `Team` for `params.team.id` already exists (created previously via the legitimate org's own `added`/`created` flow, e.g. `shopify_developers`), the `create!` block never runs, so `team.organization` is silently left as `shopify` while the request itself was authenticated as belonging to a completely different organization.

`WebhooksController#verify_signature` only authenticates that the request was signed with the secret configured for `repository_owner` (here, `params.organization.login`, the attacker's own org): [2](#0-1) [3](#0-2) 

It never checks that the signed org matches the org owning the `team.id` referenced in the body. The `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not cross-field consistency: [4](#0-3) 

Exploit flow: attacker (an admin of an org Shipit already has a webhook secret configured for) signs and POSTs `X-Github-Event: membership` with body `{action: 'removed', team: {id: <victim_team.github_id>, ...}, organization: {login: '<attacker_org>'}, member: {login: '<victim_operator_login>'}}`. `verify_signature` passes (correctly signed for attacker_org). `find_or_create_team!` matches the existing victim `Team` by `github_id` and returns it unchanged. `case params.action; when 'removed'` runs `team.members.delete(member)`, deleting the victim's `Membership` row: [5](#0-4) 

Once the row is gone, the operator immediately fails `authorized?` checks that depend on `Shipit.github_teams` membership (confirmed by existing tests asserting `authorized?` tracks `Membership` presence in `Shipit.github_teams`): [6](#0-5) 

### Impact Explanation
This lets an attacker who controls a different, Shipit-trusted organization silently deauthorize any operator belonging to another org's team, purely by knowing that team's numeric GitHub `github_id` (not secret, just an integer) and the victim's login (also not secret). It is a genuine cross-tenant mutation — one org's signed webhook mutating another org's `Team`/`Membership` state — which matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." As scoped in the question it is rated High (unauthorized de-provisioning of a legitimate operator's authorization). The action is repeatable against any team/operator pair as long as the attacker knows the target `github_id`, and blast radius spans all orgs sharing the same Shipit deployment.

### Likelihood Explanation
Preconditions: (1) the attacker administers/controls an organization that already has a configured `GithubHook::Organization` webhook secret in this Shipit instance — this is a real but non-trivial precondition, since webhook secrets are provisioned by Shipit operators per org, not self-service; (2) the attacker must know the victim team's `github_id` (discoverable via public GitHub API responses, prior webhook deliveries, or enumeration — not a Shipit secret); (3) the victim operator must currently have a `Membership` row for that team. Given a multi-org Shipit deployment (common — multiple `GithubHook::Organization` records exist per the fixtures/config), this is feasible and cheaply repeatable with no rate limiting beyond normal webhook delivery.

### Recommendation
Scope the team lookup in `find_or_create_team!` by both `github_id` and `organization` (matched against `params.organization.login`), and reject/raise if an existing `Team` with that `github_id` belongs to a different organization than the one that signed the request, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "team/organization mismatch"
  end
  team || Team.create!(github_id: params.team.id) do |t|
    t.github_team = params.team
    t.organization = params.organization.login
  end
end
```

### Proof of Concept
minitest plan (webhooks_controller_test.rb):
1. Fixtures: `shipit_teams(:shopify_developers)` with `organization: 'shopify', github_id: 1`; a second `GithubHook::Organization` fixture for org `evilcorp` with a known `secret`; `victim = shipit_users(:walrus)` with an existing `Membership` on `shopify_developers`.
2. Build payload: `{ action: 'removed', team: { id: 1, name: 'x', slug: 'x', url: 'http://x' }, organization: { login: 'evilcorp' }, member: { login: victim.login } }`.
3. Sign with `evilcorp`'s secret (`OpenSSL::HMAC.hexdigest('sha1', secret, body)`), set `X-Github-Event: membership`, `X-Hub-Signature`.
4. Assert both sides of the binding: before request, `Membership.exists?(team: shopify_developers, user: victim)` is `true` and `victim.authorized?` is `true`; POST the payload, assert `:ok`; then assert `Membership.count` decreased by 1, `Membership.exists?(team: shopify_developers, user: victim)` is `false`, and `victim.reload.authorized?` is `false` — despite the request never being signed by `shopify`'s secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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

**File:** test/models/users_test.rb (L257-265)
```ruby
    test "users are not authorized? if they aren't part of any Shipit.github_teams" do
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks)])
      refute_predicate @user, :authorized?
    end

    test "users are authorized? if they are part of any Shipit.github_teams" do
      Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)])
      assert_predicate @user, :authorized?
    end
```
