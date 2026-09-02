### Title
Membership webhooks forge arbitrary Team/Membership records when no `webhook_secret` is configured - authentication bypass - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` delegates authentication entirely to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` when no `webhook_secret` is configured for the organization. In that (documented as "optional") configuration, any unauthenticated caller can POST a forged `membership` event to `/webhooks` and `MembershipHandler#find_or_create_team!` will persist a fully attacker-authored `Team` row and add an attacker-controlled `User` to it, with zero GitHub API calls made to confirm any of it.

### Finding Description
The intended invariant is: every `Shipit::Team` row's `github_id`/`organization`/`slug` corresponds to a real GitHub team that Shipit's GitHub App actually observed via a cryptographically verified event, i.e. `Team.find_by(github_id: X).github_team == GitHub's actual team X`. This binding is enforced (if at all) only by `verify_signature`: [1](#0-0) 

which calls: [2](#0-1) 

`return true unless webhook_secret` means that for any `GitHubApp` configured without a `webhook_secret` (shown as `# nil` and described as "optional" in `docs/setup.md`, and used as the default in this repo's own test/dummy secrets), **no signature check occurs at all** — the `X-Hub-Signature` header value is never validated. Any HTTP client can hit `POST /webhooks` with `X-Github-Event: membership` and a fabricated JSON body.

`MembershipHandler` then trusts the payload completely: [3](#0-2) 

`find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)` using attacker-supplied `id`/`slug`/`name`/`url`, and `organization` from attacker-supplied `organization.login`. `process` immediately calls `team.add_member(User.find_or_create_by_login!(params.member.login))`, again from attacker-controlled data. No Octokit call is ever made — the whole record is fabricated from the webhook body.

The only remaining gate is `repository_owner` resolving to a known org via `Shipit.github(organization:)`: [4](#0-3) 

This requires the attacker to know/guess an org name matching a configured `GitHubApp` (or, in the common single-org config schema, any org name at all resolves to the sole configured app, per `github_default_organization`). This is not a secret — it is typically the company's public GitHub organization name — so it does not block the attack.

The existing test `"verifies webhook signature"` only exercises the path where a `webhook_secret` is configured and the signature explicitly fails; it does not exercise (and the suite's own default dummy secrets set `webhook_secret: nil`) the no-secret bypass path, so the divergence is not caught by current tests.

### Impact Explanation
An unauthenticated, unprivileged internet user can, in a single POST to `/webhooks`, cause the engine to persist an entirely fabricated `Shipit::Team` row (`github_id`, `slug`, `name`, `organization` all attacker-chosen) and attach an attacker-controlled `Shipit::User` to it as a member — no GitHub credentials, no session, no API token required. This is repeatable against any organization name the attacker can guess and against any fresh `github_id`. While the `Team`/`Membership` rows alone don't grant deploy access, once an operator later references that team's `id`/`slug` in `Shipit.github_teams` (`lib/shipit.rb` `github_teams`) for authorization, the attacker's forged membership becomes a real authorization grant — escalation into `Shipit.github_teams` — and since the attacker chose the `member.login`, they can insert themselves or any username into that team ahead of time. This matches the "authentication bypass (forged webhook accepted)" / "escalation into `Shipit.github_teams` authorization" impact categories, contingent on the `webhook_secret`-unset precondition.

### Likelihood Explanation
Preconditions: the deployment's `GitHubApp` for the targeted organization must have no `webhook_secret` configured. This is explicitly presented as optional in `docs/setup.md` ("Webhook secret (optional)") and is the default in this repo's `test/dummy` secrets files and `config/secrets.development.shopify.yml`/`config/secrets.development.example.yml`, so it is a realistic and likely-occurring misconfiguration for real deployments, not a contrived edge case. No secrets, tokens, or privileged roles are needed by the attacker — only knowledge of the organization login, which is generally public. The attack is a single unauthenticated HTTP POST and is fully repeatable/scriptable.

### Recommendation
Do not treat a missing `webhook_secret` as "trust all webhooks." At minimum: (1) fail closed instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature` — reject requests when no secret is configured, or require the operator to explicitly opt into unsigned webhooks; (2) require `webhook_secret` at boot/config-validation time for any configured GitHub App; (3) additionally, `MembershipHandler#find_or_create_team!` should not create authorization-bearing `Team` rows purely from webhook payload data without corroborating via the GitHub API (similar to `Team.fetch_and_create_from_github`), so a compromised/misconfigured webhook path cannot fabricate teams outright.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "unsigned membership webhook forges a team and membership when no webhook_secret is configured" do
  github_app = Shipit::GitHubApp.new('shopify', { webhook_secret: nil })
  Shipit.stubs(:github).returns(github_app)

  fresh_id = 999_999
  payload = {
    action: 'added',
    team: { id: fresh_id, name: 'Attacker Team', slug: 'attacker-team', url: 'http://evil.example.com' },
    organization: { login: 'shopify' },
    member: { login: 'attacker' },
    repository: { owner: { login: 'shopify' } }
  }.to_json

  @request.headers['X-Github-Event'] = 'membership'
  # No X-Hub-Signature header at all, or an arbitrary bogus value.

  assert_difference -> { Shipit::Team.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  team = Shipit::Team.find_by(github_id: fresh_id)
  assert team.present?
  assert_equal 'attacker-team', team.slug
  assert team.members.exists?(login: 'attacker')
end
```
Both sides of the intended equality diverge: `Team.find_by(github_id: fresh_id)` is present and contains an attacker-authored `Team`/`Membership`, while no real GitHub team with that id/slug was ever consulted (`Shipit.github.api` receives zero calls), confirming the binding "every Team row == an observed, signed GitHub team" is broken.

### Citations

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
