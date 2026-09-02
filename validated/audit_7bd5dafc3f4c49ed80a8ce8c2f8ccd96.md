Now I have enough to state the finding precisely. The core binding break is: the webhook signature is verified against the GitHub App / organization derived from `repository.owner.login` (or `organization.login`), while every default `Handler` (push, membership, pull_request, status, check_suite) acts on whatever repository/organization is named in the *same but independently-forgeable* payload fields (`repository.full_name`, `organization.login`, `team.id`), which are never cryptographically bound to the signing organization. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Webhook signature verification is scoped to `repository.owner.login`/`organization.login` but handlers act on the independently-supplied `repository.full_name`/`team.organization`, letting an org that owns any configured GitHub App forge events against a different org's repos and teams - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to verify the HMAC against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the *unverified* JSON body, then calls `Shipit.github(organization: repository_owner)` to fetch that organization's `GitHubApp` and check the signature. But the actual side-effecting code path - `Shipit::Webhooks::Handlers::Handler#repository_name` (used by `PushHandler`, pull request handlers, etc.) and `MembershipHandler#find_or_create_team!` - reads a *different* field, `repository.full_name` or `team`/`organization`, from that same body to decide which `Stack`/`Repository`/`Team` to mutate. Since the signature only proves "this body was signed by organization X's secret," and nothing ties `repository.owner.login` to `repository.full_name` or to `organization.login` cryptographically, an attacker who controls (or has been granted) a GitHub App/webhook secret for *any* organization configured in this Shipit instance can sign a payload where the "owner" field points to their own org (so the check passes) while the "full_name"/"organization" fields used by the handler point to a *different* organization's repository or team.

### Finding Description
This mirrors the reported bug class: a value used to authorize/attribute the operation (`gains`/`valueHighPoint` in the funding pool, computed once) diverges from the value actually paid out (`fees`, clamped separately) - here, the field used to *authenticate* the webhook (`repository.owner.login` / `organization.login`) diverges from the field used to *act* (`repository.full_name` for stack lookup, or the raw `organization`/`team` payload for team membership). Both fields live in the same attacker-controlled JSON body and are not bound together by the HMAC verification logic; verification only proves the *body as a whole* was signed with a particular org's secret, not that any specific field within it is internally consistent.

Concretely:
- `verify_signature` computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and asks `Shipit.github(organization: repository_owner)` for that org's `GitHubApp`, then calls `verify_webhook_signature` with that org's `webhook_secret`. [7](#0-6) 
- `Handler#repository_name` (base class for `PushHandler`, all `PullRequest::*Handler`s, `StatusHandler`) reads `payload.dig('repository', 'full_name')` and resolves `Repository.from_github_repo_name(repository_name)` to find the `Stack`s to act on - a completely separate key from the one used for signature scoping. [3](#0-2) 
- `MembershipHandler#find_or_create_team!` reads `params.team.id`/`params.organization.login` to create/find a `Team` and then adds/removes the named `member` from that team - again scoped by attacker-supplied `organization.login`, unrelated to whatever org's secret validated the request. [8](#0-7) 
- Shipit explicitly supports multiple independently-secreted GitHub Apps/organizations in one instance, each with its own `webhook_secret`, exactly the multi-tenant setup where this binding matters. [6](#0-5) 

Because `verify_webhook_signature` is a pure HMAC-over-raw-body check with `return true unless webhook_secret` and no linkage back to any specific payload field, [5](#0-4)  any org whose GitHub App is installed/configured on this Shipit instance can send `POST /webhooks` with a body that is internally inconsistent between the "owner used to pick the secret" and the "full_name/organization used to pick the target," and it will pass verification.

### Impact Explanation
This allows an attacker who controls one org's webhook secret (the org they legitimately administer/onboarded to a shared Shipit instance) to:
- Trigger `PushHandler` → `stack.sync_github` for a `Stack` belonging to a repository under a *different* organization they don't own, by setting `repository.full_name` to the victim repo while keeping `repository.owner.login` equal to their own org.
- Forge `membership` events that add/remove arbitrary GitHub logins to/from a `Team` referenced by `Shipit.github_teams`, which directly backs `User#authorized?` and thus the login-authorization gate for the whole application (`app/controllers/concerns/shipit/authentication.rb`). Adding an attacker-controlled login to a `Team` in `Shipit.github_teams` is an authorization-bypass path into the application itself. [9](#0-8) 
- Forge `pull_request`/`status`/`check_suite` events against stacks in other organizations, e.g. archiving review stacks (`ClosedHandler`) or manipulating commit statuses that feed into deploy/merge gating.

This lands squarely in the defined High-impact bucket: "escalation into `Shipit.github_teams` authorization" and potentially contributes to an "unauthorized deploy" if `sync_github`/status manipulation is chained with continuous deployment.

### Likelihood Explanation
Exploitability requires the attacker to control a `webhook_secret` for at least one organization that is configured in this Shipit deployment's `secrets.yml` `github` section - not repository write access, not a Shipit session, and not the victim organization's secret. In any deployment shared across multiple orgs/teams (the documented "Using Multiple GitHub Applications" configuration), this is a realistic unprivileged-attacker position: any onboarded team's own GitHub App admin/secret holder can act as this attacker against every other team's repos/stacks/teams on the same instance.

### Recommendation
Bind the field used to select the verification secret to the field(s) the handler actually acts on, or verify both consistently: after computing `repository_owner`, also cross-check that `repository.full_name.split('/').first` (or `organization.login` used by `MembershipHandler`) matches `repository_owner` before dispatching to handlers, rejecting the request otherwise. More robustly, resolve the target `Repository`/`Stack`/`Team` first, look up which organization it's currently registered under in Shipit's own database, and verify the signature using only that organization's secret - never trusting the payload's `owner`/`organization` field to select the secret independently from the field used to pick the target.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md` "Using Multiple GitHub Applications") with two orgs, `attacker-org` (attacker controls its GitHub App and thus knows its `webhook_secret`) and `victim-org` (owns a repo tracked by a Shipit `Stack`).
2. Attacker crafts a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner == "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC checks out - request passes. [10](#0-9) 
5. `PushHandler#process` resolves `repository_name == "victim-org/victim-repo"` via `Handler#repository_name`, finds the victim `Stack`s, and calls `stack.sync_github(expected_head_sha: ...)` - acting on a repository the attacker never proved control over. [11](#0-10) [3](#0-2) 
6. An equivalent `membership` payload with `organization.login` set to a team the attacker doesn't administer, signed with `attacker-org`'s secret, lets the attacker add their own GitHub login to that `Team`, potentially satisfying `Shipit.github_teams` membership checks in `User#authorized?`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
      end
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
