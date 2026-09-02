### Title
Cross-organization team escalation via unbound `organization`/`team.github_id` fields in `membership` webhook - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The `WebhooksController#verify_signature` selects a per-organization `webhook_secret` using a field taken directly from the untrusted JSON body, and only proves that *some* configured organization's secret signed the raw payload. It never binds that verified organization to the specific `Team` record that `MembershipHandler` mutates, so a party holding one tenant org's webhook secret can grant arbitrary GitHub logins membership in a `Team` belonging to a different, more privileged organization on the same Shipit instance.

### Finding Description
Signature verification picks the secret to check against using attacker-suppliable payload data: [1](#0-0) [2](#0-1) 

Shipit supports multiple GitHub organizations configured with independent `webhook_secret`s in the same instance, as shown by the multi-org secrets fixture: [3](#0-2) [4](#0-3) 

For a `membership` event, `repository_owner` falls back to `params.dig('organization', 'login')`, and `MembershipHandler` also reads `params.organization.login` — the HMAC only proves "this body was signed with OrgX's secret," it does not constrain which `team.id`/`team` object appears in that same, otherwise-attacker-authored JSON body: [5](#0-4) 

`find_or_create_team!` looks up (or silently reuses) a `Team` purely by the attacker-supplied `team.id` (`github_id`), and never checks that this team's real GitHub organization matches the verified `organization.login`: [6](#0-5) 

Once the (possibly pre-existing) `Team` record is resolved, `process` unconditionally adds the attacker-chosen `member.login` (auto-vivified via `User.find_or_create_by_login!`) to it: [7](#0-6) [8](#0-7) 

Team-based authorization is what gates all engine access: `User#authorized?` checks membership in any `Shipit.github_teams` team by id: [9](#0-8) 

This is the analog of the report's root cause: a value trusted for a downstream binding (`bonds[bondId].owner` in the C4 report; here, `Team`/organization identity) is set once and never re-validated against the entity actually acted upon (ERC721 transfer target vs. `owner`; here, the org that legitimately owns a `Team.github_id` vs. the org whose secret produced the signature).

### Impact Explanation
An attacker who legitimately controls the webhook secret of *any one* organization onboarded to the shared Shipit instance (a routine, low-privilege tenant) can forge a `membership` webhook whose `organization.login` matches their own org (satisfying `verify_webhook_signature`) but whose `team.id` matches the `github_id` of a `Team` already present in `Shipit.github_teams` for a *different*, higher-trust organization. `MembershipHandler#process` will add an arbitrary attacker-controlled GitHub login (`member.login`) to that team via `Team#add_member`, and that user will then satisfy `User#authorized?` and gain full access to the Shipit UI/API for stacks belonging to the victim organization — an escalation into `Shipit.github_teams` authorization performed without ever compromising the victim org's credentials.

### Likelihood Explanation
Exploitation requires: (1) the deployment to host more than one GitHub organization/tenant (a documented, supported configuration — see `secrets_double_github_app.yml`), (2) knowledge of a target `Team`'s numeric `github_id` (obtainable via GitHub's public team/org APIs or by observing existing `Team` records/URLs surfaced in Shipit itself), and (3) the attacker already legitimately holding a webhook secret for their own tenant org — no theft of another party's credentials is needed. This is a realistic risk in any multi-tenant Shipit deployment shared across organizations with differing trust levels.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the incoming `organization.login` matches the `Team`'s actual `organization` before creating or reusing it (or, more simply, look up/scope teams by `(organization, github_id)` rather than `github_id` alone, and reject the payload if an existing team with that `github_id` belongs to a different `organization`). Additionally, `WebhooksController#verify_signature` should be hardened so the org used to select the webhook secret is cryptographically or structurally bound to every organization/team-identifying field the corresponding handler subsequently trusts, not merely to the top-level `organization.login`/`repository.owner.login` value.

### Proof of Concept
1. Shipit is configured with two tenant orgs, `OrgOne` (target, has `Team` with `github_id: 555`, `organization: "OrgOne"`, and is listed in `Shipit.github_teams`) and `OrgTwo` (attacker-controlled, `webhook_secret: attacker_known_secret`).
2. Attacker POSTs to `/github_webhooks` (or the mounted webhooks path) with header `X-Github-Event: membership`, body:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "OrgTwo" },
  "member": { "login": "attacker-alt-account" }
}
```
   signed with `X-Hub-Signature: sha1=<HMAC-SHA1(attacker_known_secret, body)>`.
3. `verify_signature` computes `repository_owner` = `"OrgTwo"`, fetches `Shipit.github(organization: "OrgTwo")`, and the signature validates successfully.
4. `MembershipHandler#find_or_create_team!` finds the existing `Team` with `github_id: 555` (OrgOne's team) — no organization cross-check occurs — and `team.add_member(User.find_or_create_by_login!("attacker-alt-account"))` adds the attacker's account to it.
5. `attacker-alt-account` now passes `User#authorized?` against `Shipit.github_teams` and gains full Shipit access to OrgOne's stacks, despite the attacker never possessing any OrgOne credential.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-8)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-21)
```ruby
      class MembershipHandler < Handler
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
