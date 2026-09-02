### Title
Webhook signature verification keys off attacker-controlled JSON payload, allowing membership webhooks to forge `Shipit.github_teams` membership across organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to use for HMAC verification from a field inside the unauthenticated request body itself. In a multi-organization Shipit deployment, an attacker can direct verification to any configured organization that has no `webhook_secret` set (a documented, supported configuration) while the same payload's `team.id` — used by `MembershipHandler` to look up or create a `Team` record — is *not* re-scoped to that organization. Because `Team` lookup is keyed only on the numeric `github_id`, an attacker can attach themselves (or any GitHub login) to a `Team` row that actually maps to a different, secret-protected organization, thereby satisfying `Shipit.github_teams` authorization checks without ever having real membership in that team.

### Finding Description
The webhook signature check derives the signing organization from payload data before the payload has been verified at all:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`repository_owner` (and thus the `github_app`/secret used to validate the signature) comes straight from the untrusted JSON body — for events without a `repository` key (e.g. `membership`), it is `organization.login`, a field fully controlled by the attacker.

`GithubApp#verify_webhook_signature` short-circuits to `true` when no secret is configured for that org:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

This is a documented/supported configuration — multiple example config files ship organizations with `webhook_secret: # nil`: [3](#0-2) 

Once verification passes (trivially, for the org with no secret), the `membership` event is dispatched to `MembershipHandler`, which trusts the same attacker-controlled body to mutate team membership:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [4](#0-3) 

`Team.find_or_create_by!` matches solely on `github_id` — an integer that is globally unique across GitHub and not scoped to the organization whose secret verified the request. If a `Team` row with that `github_id` already exists (created earlier from a legitimately signed webhook belonging to a real, secret-protected organization), the block is skipped and the *existing* record is reused, and:

```ruby
member = User.find_or_create_by_login!(params.member.login)
case params.action
when 'added'
  team.add_member(member)
``` [5](#0-4) 

adds an arbitrary GitHub login as a member of that team. `User#authorized?` gates all Shipit access purely on team membership:

```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [6](#0-5) 

The binding that is broken: **"organization whose secret authenticated the webhook" ≠ "organization/team whose membership record is written."** Verification authenticates only that *some* org config (chosen by the attacker) matches, while the mutation targets a `Team` keyed independently of that org.

### Impact Explanation
This escalates into `Shipit.github_teams` authorization (an explicitly listed High-impact category): an unprivileged, unauthenticated network attacker can grant arbitrary GitHub logins membership in a Shipit-privileged team, without ever having legitimate access to that team on GitHub, purely by forging a `membership` webhook against a differently-configured (secret-less or otherwise weaker) organization in the same Shipit deployment. Once membership is granted, the attacker (after completing normal GitHub OAuth login with a matching login/`github_id`) is treated as `authorized?` and gains full application access — including triggering deploys/rollbacks on stacks gated by that team.

### Likelihood Explanation
This requires a multi-organization Shipit configuration (explicitly supported, and shown in the shipped example configs) where at least one configured organization has no `webhook_secret`, or where the attacker can otherwise obtain/guess a valid GitHub team `github_id` belonging to the target organization (team IDs are visible via GitHub's public API for teams the attacker can enumerate, and are simple sequential integers). Sending a forged `membership` webhook requires no Shipit credentials, only the public webhook endpoint URL, matching the "unprivileged attacker" scope of this review.

### Recommendation
- Determine the organization/app used for signature verification exclusively from configuration/routing that is trusted (e.g., a per-organization endpoint or an explicit installation ID resolved server-side), never from unauthenticated payload fields such as `organization.login` or `repository.owner.login`.
- Scope `Team.find_or_create_by!` lookups (and all webhook-driven mutations) to the organization that was cryptographically verified for the request, rejecting/ignoring payloads whose `organization.login`/`team` data doesn't match the verified org.
- Require `webhook_secret` to be present for every configured organization (fail closed rather than falling back to `true` when absent).

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `orgA` (has real teams gating `Shipit.github_teams`, `webhook_secret` set) and `orgB` (no `webhook_secret` configured — a supported setup per `config/secrets.development.shopify.yml`).
2. Attacker discovers the numeric GitHub `id` of `orgA`'s privileged team (e.g., via GitHub's public teams API, or because it was previously observed in legitimate webhook traffic).
3. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": <orgA_team_github_id>, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/x"},
  "organization": {"login": "orgB"},
  "member": {"login": "attacker-github-login"}
}
```
No `X-Hub-Signature` header is required (or any arbitrary value works) because `repository_owner` resolves to `"orgB"`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally.
4. `MembershipHandler#find_or_create_team!` finds the existing `Team` row for `github_id == orgA_team_github_id` (created earlier from `orgA`'s legitimate signed webhooks) and adds `attacker-github-login` as a member.
5. Attacker completes normal GitHub OAuth login with that same login; `User#authorized?` now returns `true` because they belong to a team in `Shipit.github_teams`, granting full access to stacks intended to be restricted to `orgA`'s real team members.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
