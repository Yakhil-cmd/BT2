Based on my investigation, I found a valid analog in `Shipit::MembershipHandler` and `WebhooksController`.

### Title
Membership webhook trusts payload-supplied `organization.login` for team creation while signature verification is keyed off a different payload field, allowing cross-organization team/authorization forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which webhook secret to validate a request against using `repository_owner`, parsed from the attacker-supplied JSON body (`repository.owner.login`, falling back to `organization.login`). Once signature verification passes for *that* selected organization's secret, the full untrusted JSON payload is handed to `Shipit::Webhooks::Handlers::MembershipHandler#process`, which trusts a separate field, `params.organization.login`, to decide which `Team` (and therefore which `Shipit.github_teams` authorization scope) a membership change applies to. Because the field used to select the signing key (`repository.owner.login`/`organization.login` via `repository_owner`) and the field trusted to determine the affected `Team.organization` are drawn from the same attacker-controlled JSON body but are not cryptographically bound to each other beyond "some org's secret validated," a multi-org Shipit deployment is exposed to team/membership forgery for any organization whose events flow through the same webhook endpoint, once a signature is obtained for any one configured organization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) [2](#0-1) 

`repository_owner` is entirely derived from attacker-supplied JSON (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and is used only to pick *which* configured `GithubApp`/secret to validate the HMAC against, not to constrain what the payload is allowed to say about itself.

`GitHubApp#verify_webhook_signature` further weakens this: if the selected organization has no `webhook_secret` configured, verification is bypassed entirely: [3](#0-2) 

The `membership` handler then trusts `params.organization.login` (again attacker-controlled JSON, and not necessarily the same key used above when `repository` is present) to create/select the `Team` and to add or remove a `User` from it: [4](#0-3) 

`Team` membership is the actual authorization primitive checked by `User#authorized?`, which gates access to the whole application per `Shipit.github_teams`: [5](#0-4) 

The trust binding that should hold is: *the organization whose secret validated this request* == *the organization whose team membership this payload is allowed to mutate*. Nothing enforces that equality — `verify_signature` and `MembershipHandler#find_or_create_team!` independently read organization-identifying strings out of the same untrusted JSON body, but through different paths (`repository.owner.login` vs `organization.login`), and the code never cross-checks them. In a single-org deployment this is moot because only one secret exists. In a documented multi-org configuration (`config/secrets.development.example.yml` explicitly supports `github: { someorg: {...}, someotherorg: {...} }`), each org has its own independent `webhook_secret`; an actor who can get *any one* configured org's webhook secret to validate a request (e.g., an org they legitimately administer within the same Shipit deployment, or an org configured with `webhook_secret: nil`) can submit a `membership` event payload whose `organization.login` names a *different* configured org, and whose `team`/`member` fields name any team ID and any GitHub login. `MembershipHandler#find_or_create_team!` will create or reuse a `Team` scoped to that named organization and add the named `member` to it.

### Impact Explanation
This directly escalates into `Shipit.github_teams` authorization (the explicit High-impact criterion): membership handling can add an attacker-controlled GitHub login to a `Team` that grants access, bypassing the actual GitHub organization/team membership that Shipit is meant to mirror via genuine webhooks. Because `User#authorized?` gates the entire application (`force_github_authentication`), this is an authorization-boundary crossing (a "GitHub identity"/team the app trusts vs. the actual GitHub organization state) achievable purely by controlling webhook JSON content for one configured org while naming a different org in the payload.

### Likelihood Explanation
This requires a Shipit deployment configured with multiple GitHub organizations sharing one `/webhooks` endpoint (an explicitly supported and documented configuration), and requires the attacker to be able to produce a validly-signed request for *some* configured org — either because that org has no `webhook_secret` set (`return true unless webhook_secret`), or because the attacker legitimately controls that org's GitHub App/webhook secret. Given multi-org support is a first-class documented feature and `webhook_secret` is explicitly optional per-org, this is a realistic deployment-trust gap rather than a purely theoretical one.

### Recommendation
Do not derive the organization used for `Team`/membership mutation from a separate, independently-controlled field in the payload. Bind the value used for signature-key selection (`repository_owner` in `WebhooksController`) to the value used inside each handler (e.g., pass the verified/selected organization explicitly into `Webhooks.for_event(event).each { |handler| handler.call(params, organization: repository_owner) }` and have `MembershipHandler` assert `params.organization.login == organization` before creating/mutating a `Team`). Additionally, treat a missing `webhook_secret` for a configured organization as a hard misconfiguration warning rather than a silent full bypass, or require an explicit opt-in flag for unsigned webhooks per organization.

### Proof of Concept
Preconditions: a Shipit instance configured with at least two GitHub organizations, e.g. `orgA` (attacker has valid GitHub App webhook secret for `orgA`, or `orgA.webhook_secret` is unset) and `orgB` (target org whose team membership grants access via `Shipit.github_teams`).

1. Attacker crafts a `membership` event JSON body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Shopify Developers", "slug": "developers", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "orgB" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "orgA" } }
}
```
2. Sets `X-Github-Event: membership` and computes `X-Hub-Signature` using `orgA`'s `webhook_secret` (known to the attacker as an admin of `orgA`'s installed GitHub App), or omits/mis-signs it if `orgA.webhook_secret` is nil.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'orgA')` (from `repository.owner.login`) and validates successfully against `orgA`'s secret (or bypasses validation entirely if unset), per `GitHubApp#verify_webhook_signature` at [6](#0-5) .
4. `MembershipHandler#process` runs, using `params.organization.login == 'orgB'` to create/find `Team` with `organization: 'orgB'`, and adds `User` `attacker-github-login` to that team, per [4](#0-3) .
5. If `orgB`'s team is listed in `Shipit.github_teams`, the attacker's GitHub login now satisfies `current_user.authorized?` on next login, granting access to `orgB`'s stacks despite never being added to that team on GitHub itself.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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
