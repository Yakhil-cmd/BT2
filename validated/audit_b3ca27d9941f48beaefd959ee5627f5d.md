### Title
Webhook signature verification selects the signing secret from an unverified payload field, allowing cross-organization webhook forgery in multi-tenant Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/webhook secret to validate a signature against using a field taken from the very payload it is about to verify (`repository.owner.login` or `organization.login`). The handlers that actually act on the request, however, key off a *different* field of the same payload (`repository.full_name`, or `organization.login` in `MembershipHandler`) with no check that it belongs to the organization whose secret produced a valid signature. In a Shipit instance configured for multiple GitHub organizations (a schema this engine explicitly supports), an attacker who legitimately controls the webhook secret for one configured organization can forge a signature that "authenticates" against their own org while directing the handler payload at a different organization's repository/stack, breaking the intended binding `organization used to verify signature == organization of the repository/team the handler writes to`.

### Finding Description
The verification flow is: [1](#0-0) 

`repository_owner` — the value used to select which org's `GitHubApp`/`webhook_secret` to verify against — is derived straight from the untrusted JSON body: [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct secret per organization when the multi-org schema is used: [3](#0-2) 

Once the signature check passes for the org selected by the attacker-controlled field, the *same* raw payload is dispatched, unmodified, to the registered handler(s): [4](#0-3) 

But the handlers resolve the target repository/organization from a **different** payload field that is never cross-checked against `repository_owner`: [5](#0-4) [6](#0-5) [7](#0-6) 

Since HMAC verification only proves "this body was signed with organization X's secret", not "every field inside this body pertains to organization X", nothing stops a signer from putting a different organization's repository/team identifiers inside a body they sign with their own secret.

### Impact Explanation
This engine explicitly ships and documents a multi-organization deployment schema where a single Shipit instance serves several GitHub organizations, each with its own App/webhook secret: [8](#0-7) 

In that topology, the person/team that configures and installs the GitHub App for one organization inherently knows (or chooses) that organization's `webhook_secret`. Using that secret, they can sign an arbitrary payload whose `repository.owner.login` matches their own organization (so `verify_signature` passes) but whose `repository.full_name` (or `organization.login` for membership events) points at a different, unrelated organization/repository hosted on the same Shipit instance. This lets a tenant with only their own org's webhook credentials:
- Archive/unarchive another organization's review stacks (`PullRequest::ClosedHandler`, `LabeledHandler`).
- Inject forged commit statuses for another organization's commits (`StatusHandler`), which feed into required/blocking CI checks that gate deploy safety.
- Create/modify `Team`/`User` records and team membership under an arbitrary claimed organization (`MembershipHandler`), independent of which org's secret signed the request.

These are cross-tenant writes into another repository/organization's Shipit-managed state that the attacker has no authorization over, matching the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Exploitability requires only:
1. A Shipit deployment using the multi-organization `github:` schema (explicitly documented and shipped as a first-class configuration option).
2. The attacker being a legitimate operator/installer of any one of the configured GitHub Apps (i.e., they know that org's `webhook_secret`, which they typically choose themselves when creating the App).

No GitHub App private key, `api_clients_secret`, session, or Shipit account is needed — only knowledge of one tenant's own webhook secret, which is inherent to operating a multi-tenant Shipit instance. This is a realistic and low-effort scenario for any organization that shares a Shipit deployment across teams/orgs.

### Recommendation
After `verify_signature` succeeds, bind the verified organization to the payload's effective target: reject (or re-verify) events where `repository.full_name`'s owner (or `organization.login`) does not match the `repository_owner`/organization whose secret validated the signature. Concretely, in `WebhooksController#verify_signature`, derive the actual repository owner from `repository.full_name` (splitting on `/`) rather than trusting `repository.owner.login`/`organization.login` independently, or explicitly assert equality between the two before dispatching to handlers.

### Proof of Concept
Given a Shipit instance configured with `OrgA` and `OrgB` (as in `test/dummy/config/secrets_double_github_app.yml`), where the attacker knows `OrgA`'s `webhook_secret`:

```
POST /webhooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>

{
  "action": "closed",
  "number": 1,
  "pull_request": { ...minimal valid fields..., "head": {"sha":"...","ref":"..."} },
  "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/production-app" },
  "sender": {"login": "attacker"}
}
```

- `verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates because it was produced with `OrgA`'s secret.
- `PullRequest::ClosedHandler#process` resolves `repository` from `params.repository.full_name = "OrgB/production-app"` and calls `review_stack.archive!`, affecting `OrgB`'s stack despite the request only being authenticated for `OrgA`. [9](#0-8) [10](#0-9)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```
