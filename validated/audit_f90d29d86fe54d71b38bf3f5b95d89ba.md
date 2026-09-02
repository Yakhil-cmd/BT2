## Confirmed root cause

`WebhooksController#verify_signature` selects **which GitHub App/organization's `webhook_secret`** to verify the incoming HMAC against using a value pulled from the *unverified* JSON body: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The signature is valid as long as it was computed with **whatever org's secret `repository_owner` names** — it says nothing about which org actually owns the resources the payload will mutate. Handlers, however, resolve the repository/organization to act on from **separate, independently-controlled fields of the same payload**: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

and for the `membership` event specifically, the organization that is *written* into the local `Team` record comes from `params.organization.login`, again unrelated to `repository_owner`: [4](#0-3) 

Since Shipit supports hosting **multiple independent GitHub organizations**, each with its own `webhook_secret` (see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), an attacker who legitimately controls a webhook for **their own** low-trust organization (`repository.owner.login = "AttackerOrg"`, whose secret they know) can forge a payload whose `repository.full_name` / `organization.login` fields instead name a **victim** organization/repository tracked by the same Shipit instance. The signature check passes (it's verified against `AttackerOrg`'s secret, which the attacker legitimately holds), but the handler acts on the victim's `Stack`/`Team`.

This is exactly the analog class called out in the rules: *"an organization that authenticated versus the repository that is written."* Before the fix: `authenticating_org == acted_upon_org` is assumed but never enforced. After an attacker's forged request: `authenticating_org (AttackerOrg) != acted_upon_org (VictimOrg)`, yet the code proceeds as if they were equal.

### Title
Webhook signature is verified against an attacker-chosen organization's secret while the payload's repository/organization fields (used to select stacks and grant team membership) are never checked against that authenticated organization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the `webhook_secret` to validate against using `repository.owner.login` (or `organization.login`) taken from the unauthenticated request body. Downstream handlers (`Handler#repository_name`, `MembershipHandler#find_or_create_team!`) trust a *different* field of the same, still-untrusted body (`repository.full_name`, `organization.login`) to decide which `Stack`/`Team` to mutate, without ever cross-checking it equals the organization whose secret validated the signature.

### Finding Description
Multi-tenant Shipit deployments configure one `webhook_secret` per GitHub organization (`Shipit.github(organization:)`). The controller resolves `repository_owner` purely from the JSON body and uses it only to pick the verification key: [5](#0-4) 

A valid signature only proves "this payload was signed with organization X's secret" — it proves nothing about the `repository.full_name` or `organization.login` values elsewhere in the same body, since those are attacker-controlled input, not derived from the verified identity. `Handler#repository_name` and `MembershipHandler#find_or_create_team!` use exactly those unchecked fields to select which local `Stack`/`Team` records get modified: [3](#0-2) [6](#0-5) 

Nowhere is `repository_owner` (the organization that authenticated the request) compared against `repository.full_name`'s owner or `organization.login` before the handler runs.

### Impact Explanation
An attacker who owns/administers *any* GitHub organization configured in the same Shipit instance (and therefore legitimately knows that organization's `webhook_secret`) can forge a `membership` webhook naming a victim organization in `organization.login` and an arbitrary GitHub `team.id`/`slug`, causing `Team.find_or_create_by!` to create/reuse a local `Team` scoped to the victim org and add an attacker-controlled `User` as a member via `team.add_member(member)`. If that team's handle matches one configured in `Shipit.github_teams`, the attacker's account becomes `authorized?` and passes `force_github_authentication`: [7](#0-6) [8](#0-7) 

This is escalation into `Shipit.github_teams` authorization — an explicit High-severity impact. The same cross-organization confusion also lets the attacker forge `push`/`check_suite`/`status` events against a victim's `Stack` (triggering `GithubSyncJob`, `schedule_refresh_check_runs!`, commit status writes) even though their signature only proves control of an unrelated organization.

### Likelihood Explanation
Requires only that the operator run a multi-organization Shipit instance (explicitly supported/documented, see `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`) and that the attacker control (or be a legitimate webhook admin of) at least one of the configured organizations — no privileged Shipit account, `ApiClient` token, or repository write access to the victim org is needed. This satisfies the "unprivileged attacker" bar defined in the rules.

### Recommendation
After `verify_signature` succeeds, bind the authenticated organization for the remainder of request processing and reject/ignore the event if `payload.dig('repository','owner','login')` (or `organization.login` for org-level events) does not match the organization whose secret validated the signature. Pass the authenticated organization explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, authenticated_organization:) }` and have `Handler#stacks` / `MembershipHandler#find_or_create_team!` assert equality before touching any record.

### Proof of Concept
1. Shipit is configured with two orgs, `AttackerOrg` and `VictimOrg`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker is a legitimate admin of `AttackerOrg` and knows `AttackerOrg`'s `webhook_secret` (e.g., from their own GitHub App webhook settings).
3. Attacker crafts a `membership` event body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/..." },
  "organization": { "login": "VictimOrg" },
  "member": { "login": "attacker-controlled-login" },
  "repository": { "owner": { "login": "AttackerOrg" } }
}
```
4. Attacker signs this body with `AttackerOrg`'s `webhook_secret` and POSTs to `/webhooks` with `X-Github-Event: membership` and the resulting `X-Hub-Signature`.
5. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")` and the signature validates successfully.
6. `MembershipHandler#process` runs unchanged, creating/updating a `Team` with `organization: "VictimOrg"` and adding the attacker's user as a member — as shown by `app/models/shipit/webhooks/handlers/membership_handler.rb:22-43` — despite the request never being authenticated by `VictimOrg`'s secret.
7. If `VictimOrg/deployers` is listed in `Shipit.github_teams`, the attacker's account is now `authorized?` per `app/controllers/concerns/shipit/authentication.rb:26-30`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-30)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
```

**File:** test/models/users_test.rb (L262-265)
```ruby
    test "users are authorized? if they are part of any Shipit.github_teams" do
      Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)])
      assert_predicate @user, :authorized?
    end
```
