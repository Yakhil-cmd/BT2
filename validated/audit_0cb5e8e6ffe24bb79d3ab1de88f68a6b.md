### Title
Webhook signature verification is keyed off the payload's `repository.owner.login`, not the `repository.full_name` the handlers actually act on — allows cross-organization webhook forgery in multi-org deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature against using an attacker-controlled field of the *unverified* payload (`repository.owner.login` or `organization.login`), while every webhook `Handler` resolves the repository/stack to mutate using a *different* attacker-controlled field of the same payload (`repository.full_name`). Nothing ties these two fields together, so in a Shipit instance configured with multiple GitHub organizations, an attacker who legitimately controls the webhook secret for one onboarded org can forge a payload that authenticates as that org but whose `repository.full_name` points at a completely different, victim org's repository.

### Finding Description
`Shipit.github(organization:)` supports per-organization GitHub App configuration, each with its own `webhook_secret` (`lib/shipit.rb`, `github_app_config`), as evidenced by `test/dummy/config/secrets_double_github_app.yml` defining `OrgOne`/`OrgTwo` with independent secrets. [1](#0-0) 

In `WebhooksController`, the organization used to fetch the correct signing secret is taken directly from the JSON body, before the signature has been verified: [2](#0-1) [3](#0-2) 

Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *same* raw payload to handlers. Every handler resolves the target repository/stack via `Handler#repository_name`, which reads a **different** field of the same payload: [4](#0-3) 

`Repository.from_github_repo_name` then does a straight DB lookup by the owner/name parsed out of `full_name`, with no relation back to whichever organization's secret validated the request: [5](#0-4) 

There is no code anywhere that asserts `repository.owner.login` (or `organization.login`) equals the owner segment of `repository.full_name`. The binding that should hold — *the organization whose secret authenticated the request* == *the organization owning the repository the handlers write to* — is never enforced.

### Impact Explanation
In any Shipit deployment onboarding more than one GitHub organization (an explicitly supported configuration, per `github_app_config`/`github_organizations`), an attacker who administers one onboarded org (and therefore legitimately knows/controls that org's `webhook_secret`) can sign a payload with `repository.owner.login` set to their own org, while setting `repository.full_name` to `victim-org/victim-repo`. The signature check passes (it's checked against the attacker's own org secret), but every downstream handler acts on the victim repository/stack.

Depending on the event type this enables, without any credential belonging to the victim org:
- `membership` webhooks adding/removing memberships on `Team`s used for `Shipit.github_teams` authorization — a direct escalation into the authorization system.
- `push` events queuing `GithubSyncJob` for a victim stack, and `pull_request`/`status`/`check_suite` events mutating a victim stack's commits, statuses, labels, and review-stack lifecycle (open/close/reopen/provision) — corrupting deploy-gating state (`deployable?`, `release_status`) that other flows rely on to authorize deploys.

This matches the report's bug class (an unchecked-identity/duplicate-trust binding) mapped onto the engine's "organization that authenticated versus the repository that is written" trust boundary.

### Likelihood Explanation
Requires only unprivileged control over one onboarded GitHub organization's webhook configuration (something a legitimate but malicious org owner can freely set), plus knowledge of Shipit's shared webhook endpoint and the target victim's `owner/repo` name (public information). No access to the victim org, no Shipit session, and no `ApiClient` token are required. Likelihood is limited to multi-org Shipit deployments, which is a supported and documented configuration mode, not an edge case.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the signature, cross-check that the organization used to select the webhook secret (`repository_owner`) matches the owner segment of `repository.full_name` (and of any nested `pull_request.head.repo`/`base.repo` full names used by handlers) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, derive the signing organization strictly from `repository.full_name` itself rather than from a separate `owner.login`/`organization.login` field, so there is only one payload-derived value used for both authentication and repository resolution.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `OrgOne` (attacker-administered) and `OrgTwo` (victim), each with distinct `webhook_secret`s, per `github_app_config`.
2. Attacker crafts a `membership` (or `push`/`pull_request`) webhook body:
   ```json
   {
     "action": "added",
     "organization": { "login": "OrgOne" },
     "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" },
     "team": { "id": 1, "slug": "developers", "name": "Developers", "url": "https://example.com" },
     "member": { "login": "attacker" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `OrgOne`'s known `webhook_secret` over the raw body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgOne")` (from `repository.owner.login`) and the signature verifies successfully.
5. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which resolves the team/repository via the payload and grants `attacker` membership on a team tied to `OrgTwo`'s `Shipit.github_teams` authorization — despite the attacker never having presented any `OrgTwo` credential.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
