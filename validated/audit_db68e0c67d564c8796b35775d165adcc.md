This confirms the vulnerability. Shipit explicitly supports the "Using Multiple Github Applications" configuration where each GitHub organization has its own independent `webhook_secret`, `app_id`, and `installation_id` (`config/secrets.development.example.yml:18-38`, `docs/setup.md:182-209`). This is exactly the scenario needed for a cross-repository write.

### Title
Webhook signature is verified against the organization named in the payload while handlers act on a different, unverified repository field, enabling cross-repository/cross-organization writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against based on `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), but the handlers that subsequently act on the payload resolve the target `Repository`/`Stack` using the independent `repository.full_name` field. In multi-organization Shipit deployments (the officially supported "Using Multiple Github Applications" mode), each organization has its own distinct `webhook_secret`. Because signature verification and repository resolution are keyed off two different, attacker-controlled fields of the same payload, an attacker who legitimately controls the webhook secret for one connected organization can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes with their own valid secret) while `repository.full_name` names a repository belonging to a *different* connected organization/stack, causing the handler to act on that victim stack.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end
``` [2](#0-1) 

`repository_owner` is derived from the payload itself (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), and is used to select which `GitHubApp` (and thus which per-organization `webhook_secret`) validates the HMAC signature: [3](#0-2) .

However, once the signature is accepted, `create` dispatches the full, attacker-supplied `params` to every registered handler for the event: [4](#0-3) . These handlers resolve the target `Repository`/`Stack` using a completely different payload field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

The same pattern repeats in `PushHandler` (uses `stacks` derived from `full_name`) and every `PullRequest::*Handler` (`Shipit::Repository.from_github_repo_name(params.repository.full_name)`), e.g. [6](#0-5)  and [7](#0-6) .

Because the deployment supports one `webhook_secret` per organization (as documented in `docs/setup.md:182-209` and `config/secrets.development.example.yml:18-38`, and exercised by `test/dummy/config/secrets_double_github_app.yml`), the signature only proves that *some* payload was signed by *the org named in `repository.owner.login`* — it proves nothing about `repository.full_name`, which is the field actually trusted to select which `Repository`/`Stack` record is mutated. This breaks the intended binding: `organization that authenticated == repository that is written`.

### Impact Explanation
An attacker who is an admin/owner of Organization A (a legitimate, Shipit-connected organization with its own `webhook_secret` under the multi-org config) can compute a valid HMAC signature for an arbitrary raw payload using Org A's `webhook_secret` (which they control, since GitHub lets org admins configure/view or trigger it for their own installation). By setting `repository.owner.login` to `"OrgA"` (passing signature verification) while setting `repository.full_name` to `"OrgB/victim-repo"` (a stack belonging to a different connected organization), the attacker can:
- Trigger `PushHandler` to invoke `stack.sync_github(expected_head_sha: ...)` against Organization B's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), forcing an unauthorized sync/potential deploy-triggering sequence on a repository they don't control.
- Trigger `PullRequest::OpenedHandler`/`ReopenedHandler`/`UnlabeledHandler`, etc., to provision, archive, or unarchive review stacks belonging to Organization B (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:41-54`), an unauthorized cross-organization write.

This qualifies as "cross-repository writes" / "an unauthorized deploy" under the High/Critical impact classes.

### Likelihood Explanation
Requires the attacker to control (or have webhook-secret knowledge for) at least one organization already connected to the same Shipit instance — a realistic scenario for any multi-tenant Shipit deployment serving multiple GitHub organizations, since that is an explicitly documented and supported configuration. No access to the victim organization's secret, session, or `ApiClient` token is required.

### Recommendation
Bind the fields used for authorization and the fields used for repository resolution together: after computing `repository_owner` for secret selection, re-validate that `repository.full_name`'s owner segment matches `repository_owner` (case-insensitively) before dispatching to handlers, and reject the request otherwise.

### Proof of Concept
1. Deploy Shipit with the multi-org config shown in `docs/setup.md:182-209`, connecting `OrgA` and `OrgB`, each with a distinct `webhook_secret`.
2. As an admin of `OrgA`, craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)`.
4. POST to `/github/webhooks` with `X-Github-Event: push`. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `Shipit.github(organization: "OrgA")` and validates successfully using `OrgA`'s secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` via `repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on OrgB's stack — an unauthorized cross-organization action performed using only OrgA's credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
