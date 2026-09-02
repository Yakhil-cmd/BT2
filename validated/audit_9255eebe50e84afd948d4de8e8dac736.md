### Title
Membership webhook signature/org divergence lets an attacker write `Team`/`Membership` rows for an organization they don't control - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the organization derived from `repository_owner`, which prefers `payload.dig('repository','owner','login')` over `payload.dig('organization','login')`. `MembershipHandler#find_or_create_team!` however always uses `params.organization.login` to create/find the `Team` and mutate its `Membership` rows. Because a raw JSON webhook body is fully attacker-controlled and `MembershipHandler`'s `ExplicitParameters` schema does not forbid an extra `repository` key, an attacker can supply a payload whose `repository.owner.login` names an org they legitimately control (and can sign with its own webhook secret) while `organization.login` names a different, victim organization whose `Team`/`Membership` rows get mutated.

### Finding Description
Binding claimed to hold: `organization authenticated by verify_signature` == `organization whose Team/Membership rows MembershipHandler mutates`.

- `verify_signature` computes the authenticating org as: [1](#0-0) 
which prefers `repository.owner.login` and only falls back to `organization.login` when `repository` is absent.

- It then verifies the HMAC signature using that org's own configured `webhook_secret`: [2](#0-1) [3](#0-2) 

- `MembershipHandler`, however, only requires `organization.login`, `team`, `member`, `action` in its schema - it neither requires nor forbids a `repository` key - and unconditionally uses `params.organization.login` to create the `Team` and mutate its membership: [4](#0-3) 

Real GitHub `membership` events never include a `repository` object (they are org-scoped), so in legitimate traffic `repository_owner` falls back to `organization.login` and the binding holds naturally. But because the webhook body is arbitrary attacker-supplied JSON (parsed directly with `JSON.parse(request.raw_post)` and never validated against GitHub's real event shape), an attacker can inject a spoofed `repository: {owner: {login: "attacker-org"}}` block alongside `organization: {login: "victim-org"}`. `repository_owner` then resolves to `"attacker-org"`, so `Shipit.github(organization: "attacker-org")` is used and the signature is checked against the attacker's own org's webhook secret - which the attacker knows because they legitimately administer that org/App installation. The signature check passes. Processing then proceeds to `MembershipHandler`, which reads `organization.login == "victim-org"` and creates/updates the `Team` and `Membership` rows for `victim-org`, adding the attacker's own GitHub login (`params.member.login`) as a team member there.

No existing guard closes this gap: `drop_unhandled_event` only checks the event type exists a handler for; `verify_signature`'s only check is the HMAC over the raw body against whichever org `repository_owner` names; the `ExplicitParameters` schema for `MembershipHandler` does not cross-validate against `repository`; and there is no code anywhere that asserts `repository.owner.login == organization.login` for membership events.

### Impact Explanation
An attacker who owns any organization onboarded into Shipit (and thus knows/controls its webhook secret) can forge a `membership` webhook that is authenticated as their own org but writes `Team`/`Membership` records for any other organization tracked via `Shipit.github_teams`. Since Shipit's team/membership sync (`find_or_create_team!`, `team.add_member`) drives GitHub-team-based authorization checks elsewhere in the app, this lets the attacker insert an arbitrary GitHub login (e.g., their own) into a privileged team belonging to an org they do not control - an escalation into `Shipit.github_teams` authorization for a tenant they don't own. This is repeatable against any organization name known to the attacker, at will, with no rate limiting or additional guard.

### Likelihood Explanation
Preconditions: the attacker must control at least one organization that is a valid Shipit-configured GitHub App installation (so `Shipit.github(organization: "attacker-org")` resolves and they know that org's `webhook_secret`), and must know the target victim organization's login (public information). No Shipit session, API token, or victim secret is required. The attack is a single crafted HTTP POST to `/webhooks` with a custom JSON body and a correctly computed HMAC-SHA1 signature using the attacker's own known secret - trivial and fully repeatable.

### Recommendation
In `WebhooksController#verify_signature` and/or `MembershipHandler`, require that the organization used to authenticate the webhook be the same organization the handler operates on. Concretely: for events without a repository (org-scoped events like `membership`, `team`, `organization`), derive `repository_owner` solely from `organization.login` (never prefer an unrelated/spoofable `repository` key), and additionally have `MembershipHandler` verify that `params.organization.login == repository_owner` (or otherwise re-derive/pass the authenticated org into the handler) before creating/mutating `Team`/`Membership` rows. Reject the webhook if they diverge.

### Proof of Concept
Minitest plan (webhooks controller test, no live GitHub):
1. Configure two orgs in `Shipit.github_teams`/app config: `attacker-org` (webhook secret `S_A`, known to test/attacker) and `victim-org` (webhook secret `S_V`, unknown to attacker).
2. Build payload:
```json
{
  "action": "added",
  "team": {"id": 1, "name": "Core", "slug": "core", "url": "https://api.github.com/teams/1"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
3. Compute `X-Hub-Signature` as `sha1=` + HMAC-SHA1(`S_A`, raw body) - the secret the attacker/test knows for `attacker-org`.
4. POST to `/webhooks` with header `X-Github-Event: membership`.
5. Assert response is `200 OK` (signature accepted, since `repository_owner` resolved to `attacker-org`).
6. Assert:
   - `Shipit::Team.find_by(github_id: 1)&.organization == "victim-org"` (equality broken: authenticated org is `attacker-org`, mutated org is `victim-org`).
   - `Shipit::Team.find_by(github_id: 1).members.pluck(:login)` includes `"attacker-login"`.
7. Contrast with a payload that omits `repository` entirely (real GitHub shape): here `repository_owner` falls back to `organization.login == "victim-org"`, the signature would need `S_V` (unknown to attacker), and the request is rejected with `422` - confirming the divergence is only exploitable via the injected `repository` key.

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
