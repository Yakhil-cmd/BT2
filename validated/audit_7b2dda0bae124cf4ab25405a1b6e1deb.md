## Title
Webhook signature is verified against the organization's app config, but the write target is taken from an unauthenticated `repository.full_name` field in the same payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary

## Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate the incoming request against by reading `repository_owner`, which is derived directly from the unauthenticated JSON payload: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

In multi-organization deployments, `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key in `secrets.github` [3](#0-2) . The signature is HMAC-verified against the *raw request body*, using whichever secret corresponds to `repository.owner.login`/`organization.login` in that same body.

However, once the signature check passes, every `Handler` subclass determines what to actually act on using a separate field from the same payload: `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process` and `StatusHandler#process` then act on whatever stacks/commits match that `full_name`/`sha`, e.g. triggering `sync_github` [5](#0-4)  or writing a new commit status [6](#0-5) .

Because `repository.owner.login` (used for authentication) and `repository.full_name` (used for the write) are two independent, attacker-controlled fields inside the same JSON body, nothing forces them to refer to the same repository. An attacker who legitimately controls a repository under `OrgA` (and can thus generate real, correctly-signed webhook deliveries from GitHub for that org, since they know when and how they trigger events on their own repo) can replay/craft a payload where:
- `repository.owner.login = "orgA"` (or `organization.login = "orgA"`) → selects `orgA`'s `webhook_secret` for signature verification, which will pass because the attacker really did trigger this event from their own `orgA` repo, and
- `repository.full_name = "orgB/some-other-repo"` → causes the handler to look up and mutate a completely unrelated stack belonging to `orgB`.

This breaks the intended binding: **organization that authenticated == repository that is written**. Before the fix, that equality is assumed; the code never checks it.

## Impact Explanation
Depending on the handler reached, this allows an attacker who only controls a repository in one configured GitHub organization to:
- Force `GithubSyncJob`/`sync_github` to run against a stack in a different, unrelated organization/repository via `PushHandler`, causing Shipit to re-sync commits it believes came from that push.
- Inject a fabricated commit `Status` (arbitrary `state`, `context`, `target_url`, `description`) for a commit SHA on an unrelated stack via `StatusHandler`, which downstream CI/merge-gating logic in Shipit treats as authoritative.
- Reach other handlers (`membership`, `check_suite`, `pull_request/*`) similarly keyed off `repository.full_name` while authenticated against a different org's secret, potentially manipulating team membership records, review-stack archival state, or pull-request label capture for repositories the attacker does not own.

This is a cross-repository/cross-organization write achieved purely by control of a valid webhook secret for a *different, unrelated* organization than the one whose data is modified — i.e., an unauthorized write across trust boundaries. This matches the High/Critical impact bar of "cross-repository writes" reachable without any Shipit session or API token, only requiring that a multi-org config is in use and the attacker owns/administers any one of the configured organizations (which is itself a normal, unprivileged position relative to the other organizations on the same Shipit instance).

## Likelihood Explanation
This requires:
1. The host application to be configured with the multi-organization GitHub secrets schema (`secrets.github` keyed by org, each with its own `webhook_secret`) — a documented, supported configuration [7](#0-6) .
2. The attacker to control/administer at least one of those configured GitHub organizations/repositories (enough to receive/replay a genuine webhook delivery for it).

Given those preconditions — which are exactly the threat model Shipit's multi-tenant webhook config is built for (isolating orgs from each other) — the attack requires no guessing of secrets: the attacker crafts the payload's `full_name` field independently of the field used for authentication, and GitHub's HMAC signature only covers the raw body, not any application-level invariant tying `repository.owner.login` to `repository.full_name`.

## Recommendation
In `WebhooksController`/`Handler`, after selecting the `GitHubApp` via `repository_owner` and verifying the signature, enforce that the repository being acted upon (`repository.full_name`) actually belongs to the same organization used for verification (e.g., assert `repository.full_name.split('/').first.casecmp(repository_owner) == 0`), or simplify by always deriving both values from the same single field (`repository.full_name`) rather than two independently-controlled fields.

## Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret` values, and stacks tracking repositories in both.
2. As an attacker who administers a repository under `orgA` (and thus can trigger genuine GitHub webhook deliveries signed with `orgA`'s `webhook_secret`), capture or construct a `status` (or `push`) webhook payload.
3. Modify the JSON body's `repository.full_name` to `"orgB/target-repo"` while leaving `repository.owner.login`/`organization.login` as `"orgA"`, and re-sign the modified body with `orgA`'s known `webhook_secret` (attacker knows this secret because it is provisioned to their own org's webhook).
4. Send the request to `/webhooks`. `verify_signature` computes `Shipit.github(organization: "orgA")` and successfully verifies the signature against `orgA`'s secret.
5. `StatusHandler#process` (or `PushHandler#process`) resolves `Repository.from_github_repo_name("orgB/target-repo")` and writes a commit status / triggers a sync for `orgB`'s stack, even though the request was never authenticated by `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
