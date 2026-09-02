Based on my research, I found a concrete vulnerability in the webhook signature verification binding.

### Title
Membership webhook signature verified against attacker-chosen `repository.owner.login`, while team membership writes trust an unrelated `organization.login` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub organization's `webhook_secret` to validate the HMAC signature against using `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')` only if `repository` is absent [1](#0-0) [2](#0-1) . `Shipit::Webhooks::Handlers::MembershipHandler`, however, never looks at `repository` at all: it creates/finds the `Team` and adds the member using `params.organization.login` and `params.team.id` exclusively [3](#0-2) . Because the JSON body is attacker-supplied and only `.dig`-accessed (no schema enforcement of `repository` for this handler), the field used to select the *authenticating* organization (`repository.owner.login`) and the field used to select the *organization/team being written* (`organization.login`) are never checked for equality.

### Finding Description
`GithubApp#verify_webhook_signature` returns a boolean HMAC comparison, and the app config (including `webhook_secret`) is looked up per-organization via `Shipit.github(organization: repository_owner)` [4](#0-3) . Multiple GitHub organizations can be configured on one Shipit instance, each with its own `webhook_secret`, and `Shipit.github(organization:)` raises `GithubOrganizationUnknown` for unrecognized orgs [5](#0-4) , confirming per-organization credential scoping is a supported deployment model.

An attacker who is a legitimate member/admin of one onboarded organization ("Org A") knows Org A's `webhook_secret` and can compute a valid `X-Hub-Signature`. Nothing stops them from crafting a `membership` event payload that includes a spoofed `repository.owner.login: "OrgA"` (satisfied only to pass `verify_signature`) together with `organization.login: "OrgB"`, an arbitrary `team.id` (a real GitHub team numeric id, discoverable via GitHub's public API), and `member.login: <attacker's own Shipit login>`. `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`, and `process` calls `team.add_member(member)` for `action == 'added'` — none of this checks that the verified `repository_owner`/organization matches `params.organization.login` [6](#0-5) .

### Impact Explanation
If the targeted `Team` (Org B's) is one of the teams configured in `Shipit.github_teams`, `User#authorized?` becomes true once the attacker is added as a member: `@authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) . This is a direct escalation into `Shipit.github_teams` authorization using only a webhook secret the attacker legitimately possesses for an unrelated organization on the same multi-tenant Shipit instance — matching the High-impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Requires: (1) a Shipit deployment onboarding more than one GitHub organization (each with independent GitHub App credentials/`webhook_secret`), and (2) the attacker having legitimate control of one of these organizations' webhook secret (e.g., they are an org admin of a smaller/less-trusted tenant on a shared Shipit instance). No cross-tenant repository/session access, no privileged Shipit account, and no `ApiClient` token are needed — only the webhook endpoint and a secret for any one onboarded org.

### Recommendation
In `MembershipHandler` (and any other handler keying off `organization.login`), cross-validate that `params.organization.login` (or `params.repository.owner.login` when present) equals the `repository_owner`/organization value that `WebhooksController#verify_signature` used to select the signing secret, rejecting the request otherwise. More generally, `verify_signature` should authenticate using the same field(s) actually consumed by each event's handler, rather than a `repository`-first fallback that a `membership` handler never reads.

### Proof of Concept
1. Attacker is an admin of "OrgA", onboarded on the shared Shipit instance with its own `webhook_secret`.
2. Attacker computes `sha1=<hmac>` over a JSON body using OrgA's `webhook_secret`:
```json
{
  "repository": { "owner": { "login": "OrgA" } },
  "action": "added",
  "organization": { "login": "OrgB" },
  "team": { "id": 12345, "name": "OrgB Deployers", "slug": "deployers", "url": "https://api.github.com/teams/12345" },
  "member": { "login": "attacker-shipit-login" }
}
```
3. POST to `/webhooks` with `X-Github-Event: membership` and the computed `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner = "OrgA"` and validates successfully against OrgA's secret [1](#0-0) .
5. `MembershipHandler#process` runs, finds/creates `Team` with `github_id: 12345, organization: "OrgB"` and adds `attacker-shipit-login` as a member [6](#0-5) .
6. If team 12345 is in `Shipit.github_teams`, the attacker's user now passes `User#authorized?`.

Note: I was unable to fully read `lib/shipit.rb`'s multi-organization configuration block (tool read failed on the final iteration), so the exact mechanism for enumerating/whitelisting multiple onboarded organizations is inferred from `Shipit.github(organization:)`/`GithubOrganizationUnknown` usage and test fixtures rather than direct inspection of the config loader.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
