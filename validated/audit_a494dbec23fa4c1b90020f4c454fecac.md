### Title
Unauthenticated forged webhook events escalate into `Shipit.github_teams` authorization when `webhook_secret` is unset - ([File: lib/shipit/github_app.rb])

### Summary
The reported bug class ("use `call` instead of `transfer`") is really about a security control that silently degrades to a weaker/no-op mode under normal, permitted configuration. `shipit-engine` has an analogous defense-in-depth collapse: `GithubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatic success, and the organization used to select that secret is itself read from the unauthenticated webhook body. This lets an unauthenticated attacker submit a forged webhook that is processed by `Shipit::Webhooks::Handlers::MembershipHandler`, mutating `Team`/`Membership` records that back `Shipit.github_teams` authorization — the equality broken is "organization that authenticated the request" == "organization whose data is written/trusted."

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config to use for verification straight out of the unsigned, attacker-controlled JSON body: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` then unconditionally accepts the request if that organization's `webhook_secret` is blank: [3](#0-2) 

`webhook_secret` is documented as optional ("If you've set a webhook secret ... you should copy it here"), and shipped example/dummy configs leave it `nil`: [4](#0-3) [5](#0-4) [6](#0-5) 

Once verification is a no-op, the full unsigned payload is routed to registered handlers, including `MembershipHandler`, which finds-or-creates a `Team` keyed only by `github_id` and appends an arbitrary `User` to it: [7](#0-6) 

Because `Team.find_or_create_by!(github_id: ...)` matches purely on `github_id` (not organization), an attacker who knows/guesses the `github_id` of a team already used for authorization can reuse that id to have the *existing*, already-authorized `Team` record found and have `team.add_member(member)` append an attacker-chosen `User`: [8](#0-7) 

That authorization is precisely what gates access to the app: [9](#0-8) 

The binding broken: "the GitHub organization whose signature nominally authenticated the request" is supposed to equal "the organization/team data the handler is permitted to write," but when `webhook_secret` is unset the signature check contributes nothing, so any organization name in the payload authenticates equally well — including one whose associated handler side effects (Team membership) govern the engine's own authorization model.

### Impact Explanation
This escalates an unauthenticated network attacker directly into `Shipit.github_teams` authorization, matching the explicitly in-scope High-impact class ("escalation into `Shipit.github_teams` authorization"). Once a user is a member of an authorized `Team`, `User#authorized?` returns true and the attacker's GitHub identity gains access to the gated Shipit UI/actions (which can lead to triggering deploys/rollbacks depending on further authorization checks) without ever presenting a valid GitHub App/webhook credential.

### Likelihood Explanation
Requires that the operator has not configured a `webhook_secret` for the relevant organization — a state the engine's own documentation and shipped example configs present as normal/optional rather than a misconfiguration, and that the attacker can guess or discover the `github_id` of an already-authorized team (often discoverable via GitHub's own team/org API for public teams, or via prior legitimate webhook traffic). This is a plausible, moderate-likelihood scenario rather than a purely theoretical one, consistent with the moderate likelihood scored in the source report.

### Recommendation
- Make `verify_webhook_signature` fail closed: never return `true` for a missing signature/secret combination; require an explicit, deliberate "unsigned mode" opt-in rather than defaulting to always-accept.
- Do not derive the organization used for verification from the same unauthenticated payload that will later be trusted for writes; if verification and the eventual mutation use different provenance, cross-check that the verified organization matches the organization the handler is about to mutate (e.g., `MembershipHandler` should confirm `params.organization.login` equals `repository_owner`/the organization whose key verified the request).
- Scope `Team.find_or_create_by!` to also match on `organization`, not just `github_id`, so a forged event for org A cannot resolve to a `Team` legitimately owned by org B.

### Proof of Concept
1. Target a Shipit deployment where an organization entry in `Shipit.github` config has `webhook_secret` unset (a documented, supported configuration, e.g. as in `test/dummy/config/secrets.yml`).
2. Discover the `github_id` of a `Team` already tied to `Shipit.github_teams` (e.g., via GitHub's public teams API, or by observing team ids surfaced in the Shipit UI).
3. POST to `/webhooks` with `X-Github-Event: membership` and a body such as:
```json
{
  "action": "added",
  "team": {"id": <known_authorized_github_id>, "name": "x", "slug": "x", "url": "https://api.github.com/x"},
  "organization": {"login": "<org-without-webhook_secret>"},
  "member": {"login": "<attacker-github-login>"}
}
```
with no valid `X-Hub-Signature` header (or any garbage value).
4. `verify_signature` resolves the app for `organization.login`, finds `webhook_secret` blank, and `verify_webhook_signature` returns `true` unconditionally: [10](#0-9) 
5. `MembershipHandler#process` runs, finds the existing authorized `Team` by `github_id`, and adds the attacker's `User` as a member: [11](#0-10) 
6. The attacker's GitHub identity now satisfies `User#authorized?` and is granted access gated by `Shipit.github_teams`.

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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** test/dummy/config/secrets.yml (L8-13)
```yaml
  github:
    domain: # defaults to github.com
    app_id: 42
    installation_id: 43
    bot_login: "shipit[bot]"
    webhook_secret: # nil
```

**File:** config/secrets.development.shopify.yml (L5-9)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
