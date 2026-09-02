### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but handlers act on the repository from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App deployment (`Shipit.github(organization:)` keyed configuration), the HMAC signature check that authenticates an inbound webhook is bound to a different field of the payload than the field actually used to select which `Stack`/`Repository` the webhook payload acts on. This breaks the intended binding: "the organization that authenticated" must equal "the repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) using: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end
```

where: [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

After signature verification succeeds, the raw JSON payload is dispatched unmodified to handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`), and every handler resolves the target `Stack` via `Handler#repository_name`, which reads a **different** field: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Shipit.github` resolves per-organization configs and secrets (documented multi-org setup, e.g. `test/dummy/config/secrets_double_github_app.yml`, and `lib/shipit.rb#github`/`github_app_config`): [4](#0-3) 

There is no code path that cross-checks that `repository.owner.login` (used to pick the verifying secret) matches the owner encoded in `repository.full_name` (used to pick the actually-affected `Stack`). An attacker who is a legitimate administrator of one organization configured on the same multi-tenant Shipit instance (Org A) knows Org A's `webhook_secret` (it is something the org admin configures when installing the GitHub App) and can therefore compute a valid `X-Hub-Signature` for any payload as long as `repository.owner.login`/`organization.login` is set to "Org A". However, nothing forces `repository.full_name` to also belong to Org A — the attacker can set `full_name` to `"OrgB/victim-repo"` while keeping `owner.login` = `"OrgA"`. The signature check passes (verified with Org A's known secret), but `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. operate on `Repository.from_github_repo_name("OrgB/victim-repo")`.

### Impact Explanation
This lets an attacker with legitimate (but limited) admin rights over one configured organization on a shared Shipit instance forge webhook events against a `Stack` belonging to a completely different, unrelated organization. Concretely, via `PushHandler`, the attacker can call `stack.sync_github(expected_head_sha: ...)` on a victim's stack, forcing it to sync to an attacker-chosen SHA and, if `continuous_deployment` is enabled, trigger an unauthorized deploy of that SHA on the victim stack. Via `StatusHandler` an attacker can forge CI status for a victim's commit (`commit.create_status_from_github!`), influencing deploy gating (`require_ci`) and potentially unlocking a deploy that shouldn't be shippable. This crosses the "authorization for repository A obtained implicitly authorizes writes to repository B" boundary, i.e., cross-repository/cross-organization writes and an unauthorized deploy trigger, which map to the Critical/High categories defined in the rules.

### Likelihood Explanation
This requires: (1) the target Shipit instance to be configured with multiple GitHub Apps/organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications"), and (2) the attacker to control/administer at least one of those organizations (and thus know its `webhook_secret`) while a victim stack exists under a different configured organization on the same instance. This is a realistic scenario for shared/internal deployment platforms serving multiple teams/orgs with separate GitHub App installations. It requires no Shipit session, API token, or GitHub App private key — only knowledge of one organization's own webhook secret, which that organization's own admin necessarily possesses.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`#stacks`), enforce that the organization used to select the verifying `GitHubApp`/secret is the same organization embedded in `repository.full_name` (and in `organization.login` for org-level events). Reject the webhook if these disagree, e.g.:
```ruby
def repository_owner
  full_name_owner = params.dig('repository', 'full_name')&.split('/')&.first
  declared_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
  return nil if full_name_owner && declared_owner && full_name_owner.casecmp(declared_owner) != 0
  declared_owner
end
```

### Proof of Concept
Given a Shipit instance configured with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications"), and a victim `Stack` belonging to `OrgB/victim-repo`:

1. Attacker is an admin of `OrgA` and knows `OrgA`'s `webhook_secret` (they configured the GitHub App for their own org).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner` = `"OrgA"`, looks up `Shipit.github(organization: "OrgA")`, and verifies successfully against the attacker-known secret [5](#0-4) .
5. `PushHandler#process` is invoked with the full payload and resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` [3](#0-2) [6](#0-5) , causing `OrgB`'s stack to sync/deploy to the attacker-chosen `after` SHA, despite the signature having been verified against `OrgA`'s secret rather than `OrgB`'s.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
