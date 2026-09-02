### Title
Webhook signature verification is scoped to the wrong field, allowing cross-organization team-membership and stack forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a GitHub webhook signature against using a value pulled from the JSON body itself (`repository.owner.login` or, if absent, `organization.login`). However, none of the event handlers that subsequently mutate state (`MembershipHandler`, `Handler#repository_name`/`PushHandler`, PR handlers, etc.) re-validate that the entity they act on (`team.id`, `repository.full_name`) actually belongs to that same, cryptographically-authenticated organization. Any customer who legitimately administers one Shipit-tracked GitHub organization (and therefore legitimately knows that org's `webhook_secret`) can forge a webhook whose signature-selection field claims their own org, while the payload's `team.id`/`repository.full_name` field refers to a *different*, victim organization/stack tracked by the same Shipit instance.

### Finding Description
`verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This only proves "the request was signed with the secret belonging to the organization named in this field of the body." It does not prove that any *other* field of the same body (which is otherwise fully attacker-controlled once they know one org's secret) actually pertains to that organization.

Handlers, however, key their side effects off unrelated fields:

- `MembershipHandler#find_or_create_team!` looks up/creates a `Team` purely by the globally-unique GitHub `team.id`, and `team.organization = params.organization.login` is only used on first creation — an *existing* team row (e.g. one of the teams listed in `Shipit.github_teams`, used for application-wide authorization) is matched by `github_id` alone, independent of `organization.login`: [2](#0-1) 

- Generic handlers resolve the acted-upon repository via `payload.dig('repository', 'full_name')`, a field completely separate from `repository.owner.login` used for signature-org selection: [3](#0-2) 

- `PushHandler` uses that `repository_name`-derived `stacks` scope to trigger a GitHub sync job on whatever stack matches, regardless of which organization's secret signed the request: [4](#0-3) 

Because Shipit is multi-tenant (`Shipit.github(organization:)` resolves a distinct GitHub App/`webhook_secret` per organization, per `lib/shipit/github_app.rb`), a customer who legitimately owns one tracked organization's webhook secret can:
1. Set `organization.login` (or `repository.owner.login`) to their own org, so `verify_signature` picks their own known secret and the HMAC passes.
2. Set `team.id` to the numeric GitHub team ID of a team belonging to a different, victim organization already tracked by this Shipit instance (team IDs are global, sequential GitHub object IDs, not org-scoped secrets).
3. Set `member.login` to their own GitHub login and `action: "added"`.

`MembershipHandler` will find the victim's existing `Team` row by `github_id` and add the attacker as a member — with no relationship to the organization whose secret actually signed the request.

### Impact Explanation
`Shipit::User#authorized?` grants application access based on membership in `Shipit.github_teams`:
```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [5](#0-4) 
and `Shipit::Authentication#force_github_authentication` enforces this on every controller action. [6](#0-5) 

Forging a `membership` "added" event that targets one of the `Shipit.github_teams` team IDs lets the attacker grant themselves (or an arbitrary GitHub login) authorized access to the whole Shipit instance — this is the "escalation into `Shipit.github_teams` authorization" High-impact class. The same signature/entity decoupling also lets an org admin trigger `sync_github`/pull-request state mutations on stacks belonging to a different organization's repository (`repository.full_name` vs. `repository.owner.login`), matching the "cross-repository writes" Critical-impact class, since these mutations are not scoped back to the signing organization.

### Likelihood Explanation
The attacker only needs to legitimately administer (or otherwise obtain the `webhook_secret` of) one GitHub organization already configured against this Shipit instance — an expected, low-privilege position in a multi-tenant Shipit deployment. GitHub team IDs are unauthenticated, sequential, discoverable identifiers (visible via the GitHub API/UI for any team the attacker or a collaborator can see, or simply brute-forceable), so no secret information about the victim organization is required. No repository write access, GitHub App private key, or Shipit session/API token is needed — only the ability to POST a crafted JSON body with a valid `X-Hub-Signature` computed from a secret the attacker legitimately possesses.

### Recommendation
Bind the organization used for signature verification to every field a handler subsequently trusts:
- After computing `repository_owner` for signature selection, re-derive and cross-check the *same* organization against `repository.full_name`'s owner segment (for repo-based handlers) and against `team.organization`/the org that actually owns `team.id` (for `MembershipHandler`), rejecting the webhook (422) on mismatch.
- For `MembershipHandler`, scope the `Team.find_or_create_by!` lookup by both `github_id` **and** `organization: params.organization.login`, and refuse to attach members to an existing team whose recorded `organization` differs from the organization that signed the request.
- More generally, treat `X-Hub-Signature` verification as authenticating the specific organization/repository claimed by the *primary* identifying fields the handlers use, not an independent field that happens to appear elsewhere in the same JSON body.

### Proof of Concept
1. Shipit instance tracks two organizations, `attacker-org` (attacker is an admin, knows its `webhook_secret`) and `victim-org` (unrelated, tracked separately, with a team `victim-org/admins` listed in `Shipit.github_teams`).
2. Attacker looks up `victim-org/admins`'s numeric GitHub team `id` (e.g., via the public/API team page).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": <victim_team_github_id>, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/<id>" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-login" }
}
```
   signed with `attacker-org`'s known `webhook_secret` as `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC matches — request is accepted.
5. `MembershipHandler#find_or_create_team!` finds the existing `victim-org/admins` `Team` row by `github_id` (ignoring `organization.login`) and `team.add_member(User.find_or_create_by_login!("attacker-login"))` runs, adding the attacker to a team that grants `Shipit.github_teams` authorization for the whole instance.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
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
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
