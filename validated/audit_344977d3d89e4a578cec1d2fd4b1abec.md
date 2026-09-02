The `MembershipHandler` reveals the analog that matches this bug class.

### Title
Membership webhooks let any organization forge team membership for a repository-scoped team — organization authenticated vs. organization written mismatch - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
The `membership` webhook event is authenticated per-organization (`WebhooksController#verify_signature` picks the signing secret based on `organization.login` or `repository.owner.login` from the payload), but `MembershipHandler` trusts the `organization.login` field embedded in the same payload to attribute team membership, without re-checking that the organization that signed the request is the org the team actually belongs to when a `Team` with that `github_id` already exists but was created under a different org context, or when Shipit is configured with several GitHub Apps/orgs sharing a global `Team`/`User` namespace.

### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification directly from attacker-supplied payload fields: [1](#0-0) 
That is the "organization authenticated" side of the binding. Once verified, `MembershipHandler#process` uses `params.organization.login` from the very same JSON body to set `team.organization` and to add/remove a `member` (a global `User`, looked up/created by login only) to/from a `Team` keyed solely by `github_id`: [2](#0-1) 
`Team` and `User` records are global (not scoped per GitHub App/organization config) in this engine: `User.find_or_create_by_login!` matches on `login` alone, and `find_or_create_team!` matches on `github_id` alone. If Shipit is configured to serve multiple GitHub organizations (as the multi-org config documented in `config/secrets.development.example.yml` allows), a webhook correctly signed by Organization A's `webhook_secret` (the org that "authenticated") can create/modify a `Team` record and its membership that is then used for `Shipit.github_teams` authorization checks across the whole installation — i.e., the organization whose webhook secret validated the request is not necessarily bound to the organization whose team/membership state is being mutated, because the same `Team`/`User` tables and `github_id`/`login` keys are shared globally across all configured organizations.

This is the same class of bug as the reported finding: a field used to compute an authorization-relevant quantity (`availableBorrowPart`/`collateralShare` bounded by the user's actual collateral) is trusted without checking it stays within the bound established by a different, more privileged quantity (the user's real collateral share). Here, the quantity trusted without a matching check is the organization identity used to grant `Shipit.github_teams` membership, while the actual verified/privileged binding is "this specific organization's secret was used."

### Impact Explanation
`User#authorized?` gates OAuth login/session access strictly on team membership computed from `Shipit.github_teams`: [3](#0-2) 
If an attacker (or a compromised/lower-trust org in a multi-org deployment) can forge or trigger a `membership` webhook that is validly signed for their own organization but whose payload names a `Team`/`github_id` belonging to a privileged team, they could escalate a `User` into `Shipit.github_teams`, escalating access into stack authorization for repositories they do not own. This maps to the report's "High: escalation into `Shipit.github_teams` authorization" impact category.

### Likelihood Explanation
This requires: (1) a Shipit deployment configured with multiple GitHub Apps/organizations (a documented, supported configuration), and (2) the attacker's organization having a legitimate, working webhook (i.e., valid `webhook_secret` for their own org — which any org admin installing the app already has). No repository write access, no `ApiClient` token, and no session are required — only the ability to fire a `membership` event from an organization the attacker administers, whose webhook is registered against the same Shipit instance. This is a plausible but not trivial precondition (multi-org hosting), which is directly acknowledged and supported by the engine's own configuration surface, so likelihood is moderate rather than high.

### Recommendation
Scope `Team` records (and `User`↔`Team` membership) by the originating GitHub App/organization login, and have `MembershipHandler` verify that `params.organization.login` matches the `repository_owner`/organization resolved and authenticated by `WebhooksController#verify_signature` before creating or mutating team membership, rather than trusting the organization name embedded in the payload body alone.

### Proof of Concept
Not independently runnable from the indexed engine code alone (requires a live multi-organization Shipit deployment with two distinct configured GitHub Apps sharing one instance, plus test fixtures/db access to demonstrate the `github_id` collision or organization confusion). Conceptually:
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org format).
2. As an admin of `orgA` (attacker-controlled), send a `membership` webhook, correctly HMAC-signed with `orgA`'s `webhook_secret`, but with `team.id` matching a `Team.github_id` that is actually `orgB`'s privileged team (or with `organization.login` set to `orgB`) and `member.login` set to the attacker's own `User`.
3. `WebhooksController#verify_signature` passes because the signature is valid for `orgA`.
4. `MembershipHandler#process` calls `Team.find_or_create_by!(github_id: params.team.id)` and adds the attacker as a member without checking the authenticated org matches, since `Team`/`User` records are global across the installation. [4](#0-3) 

**Caveat**: I could not fully verify how `Shipit.github_teams` config maps `Team` records to specific organizations in a multi-org deployment (i.e., whether `Shipit.github_teams` itself is also global or per-org), which affects the exact severity of this finding. This would require deeper inspection of `Shipit.github_teams` configuration loading, which was not fully covered in the available index; a Devin session with full repo access would be needed to confirm this precisely before treating this as a confirmed exploitable vulnerability versus a defense-in-depth gap.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
