### Title
Webhook signature verified against attacker-selected organization while payload actions target an unverified repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate the HMAC signature against using an attacker-controlled, unverified field (`repository.owner.login` / `organization.login`), while the code that actually acts on the payload (selecting the `Repository`/`Stack` to sync, close, label, etc.) reads a *different* unverified field, `repository.full_name`. These two fields are never cross-checked, so a valid signature computed with organization A's secret does not guarantee the payload's actions are confined to organization A's repositories.

### Finding Description
`Shipit::WebhooksController#verify_signature` resolves the GitHub App configuration to verify against like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization secret from `secrets.github[organization]` [3](#0-2) . This multi-organization config schema is the documented, supported configuration (see `config/secrets.development.example.yml` showing multiple orgs each with their own `webhook_secret`).

Once the signature is verified, the full JSON body is parsed and dispatched to event handlers: [4](#0-3) 

Every handler, however, determines which `Repository`/`Stack` to operate on using a *different* field from the same payload — `repository.full_name` — via `Handler#repository_name`/`Handler#stacks`: [5](#0-4) 

and directly in individual handlers, e.g. `PullRequest::ClosedHandler#repository`, `PullRequest::OpenedHandler#repository`, `PullRequest::EditedHandler#repository`: [6](#0-5) [7](#0-6) 

`repository.owner.login` (used only for secret selection) and `repository.full_name` (used to select the actual repository being acted on) are independent JSON fields inside the same webhook body — nothing forces `full_name` to start with `owner.login`. The binding that should hold is:

`organization whose secret authenticated the request == organization of the repository being written to`

but the code never enforces this equality. An attacker who legitimately controls (or knows the webhook secret of) organization A — e.g., they administer their own GitHub App/organization configured in Shipit, or they have obtained/leaked org A's `webhook_secret` through means outside Shipit's control but without any Shipit credentials — can sign an HTTP POST to `/webhooks` with:
- `repository.owner.login = "OrgA"` (or `organization.login = "OrgA"`) so `verify_signature` selects OrgA's `webhook_secret` and the HMAC computed with the known secret validates,
- `repository.full_name = "OrgB/some-repo"` inside the same JSON body,

and Shipit will process the event (e.g. `PushHandler`, `pull_request` handlers, `StatusHandler`) against `OrgB`'s `Repository`/`Stack`/`Commit` records — an organization the attacker never authenticated for.

### Impact Explanation
Handlers triggered this way can archive/unarchive review stacks, force `GithubSyncJob` to sync a stack against an attacker-chosen `expected_head_sha` (`PushHandler#process` → `stack.sync_github(expected_head_sha: params.after)`), inject fabricated commit statuses (`StatusHandler`), or manipulate pull-request-tracking state — all scoped to a repository belonging to a different, unauthorized GitHub organization than the one whose secret was used to authenticate the webhook. This is a cross-repository/cross-organization write achieved by crossing an authentication boundary that the application believes it enforces via HMAC verification, satisfying the "cross-repository writes" Critical impact criterion, contingent on Shipit being configured for more than one GitHub organization (the documented multi-org secrets schema) and the attacker knowing at least one configured org's webhook secret.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (a documented, supported configuration), and (2) the attacker possessing knowledge of one configured organization's `webhook_secret` — plausible if the attacker administers their own GitHub App/org onboarded into the shared Shipit instance, or if webhook secrets are non-uniformly protected/leaked, which is a realistic operational scenario for multi-tenant Shipit deployments. No Shipit session, `ApiClient` token, or repository write access on the *target* org's GitHub repo is needed.

### Recommendation
After signature verification succeeds, re-derive the acting organization strictly from `repository.full_name`/`repository.owner.login` and assert it matches the organization whose secret was used to verify the signature (i.e., bind `repository_owner` and the owner segment of `repository.full_name` to be identical before dispatching to handlers), rejecting the webhook with `422` on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema).
2. As an operator with knowledge of `orga`'s `webhook_secret` (e.g., you administer the GitHub App for `orga`), craft a JSON payload for a `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "orgb/target-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(orga_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orga")` and validates successfully against the known `orga` secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgb/target-repo")` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: params.after)` on `orgb`'s stack — an action never authorized by `orgb`'s own webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
