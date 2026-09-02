### Title
Webhook signature is verified against an organization derived from `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field, allowing cross-tenant webhook forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` configured with one `github:` entry per GitHub organization, each with its own `webhook_secret`), `WebhooksController#verify_signature` selects which organization's secret to use for HMAC verification based on `repository_owner`, i.e. `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). However, none of the actual event handlers (`PushHandler`, `StatusHandler`, pull-request handlers, `MembershipHandler`, etc.) use that same field to resolve which repository/stack/team to act on — they instead use `payload.dig('repository', 'full_name')` (or, for `membership`, an independent `organization`/`team` payload) with no cross-check that it belongs to the organization whose secret verified the signature.

### Finding Description
The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization that owns the repository/stack being mutated`

`verify_signature` establishes the left-hand side: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key when multi-org config is used: [3](#0-2) 

But `Handler#repository_name`/`#stacks` (used by `PushHandler` and inherited by all other handlers) resolves the right-hand side from a completely separate JSON field with no relation enforced to `repository.owner.login`: [4](#0-3) [5](#0-4) 

The same pattern repeats in the pull-request handlers, which independently pull `params.repository.full_name` to resolve the `Repository`/stack to archive, unarchive, or update pull-request metadata for: [6](#0-5) [7](#0-6) 

Because JSON payload fields are entirely attacker-controlled (the attacker crafts the raw POST body themselves and just needs a signature that matches whichever secret is picked), an attacker who is the administrator of *any one* organization configured in the shared Shipit instance (and therefore knows/controls that organization's `webhook_secret`, which is self-configured when registering the GitHub App used for that org) can:
1. Set `repository.owner.login` (or `organization.login`) to their own organization, so `verify_signature` selects their own known `webhook_secret` and the signature check passes.
2. Set `repository.full_name` (used by every handler) to point at a completely different, victim organization's repository that is tracked by the same shared Shipit instance.

The multi-org configuration schema explicitly exists and is documented for this exact "shared instance, multiple GitHub orgs" use case: [8](#0-7) [9](#0-8) 

### Impact Explanation
This breaks the deployment-trust binding between "the organization that authenticated the webhook" and "the repository being written to" — this is a cross-repository / cross-tenant write. Concretely, with a forged signature the attacker can, on a victim's stack that they have no access to:
- Force a `push` event to trigger `stack.sync_github` against an arbitrary victim commit SHA [5](#0-4) 
- Inject/forge commit statuses on victim commits via the `status` handler, which affect deployability checks used to gate deploys (`Commit#deployable?`), potentially allowing an unauthorized deploy to be triggered later.
- Archive/unarchive victim review stacks or otherwise mutate victim `PullRequest`/`ReviewStack` state via the pull-request family of handlers.
- Trigger membership/team side effects via the `membership` handler, which can affect `User#authorized?` checks tied to `Shipit.github_teams`.

This matches the "Critical: cross-repository writes / unauthorized deploy" and "High: unauthenticated read/write of stack state" impact tiers defined in scope, since the write is performed against a stack the attacker's authenticated organization does not own.

### Likelihood Explanation
This requires the host to be running Shipit in the documented multi-organization configuration (one `webhook_secret` per org) — a supported, documented deployment mode, not a misconfiguration outside the engine's control. Any attacker who legitimately administers one tenant organization's GitHub App (and thus its `webhook_secret`) can exploit this against every other tenant sharing the same Shipit instance, with a single crafted HTTP request; no GitHub session, `ApiClient` token, or `webhook_secret` of the victim org is needed.

### Recommendation
After selecting the `GitHubApp`/secret via `repository_owner` and verifying the signature, re-validate that the same authenticated organization matches the owner segment of `repository.full_name` (and any other repository/organization identifiers consumed downstream by handlers) before dispatching to `Shipit::Webhooks.for_event(event)`. Reject the webhook if the two disagree.

### Proof of Concept
Given a Shipit instance configured with two organizations, `OrgOne` (attacker-controlled, secret known to attacker) and `OrgTwo` (victim, owns a tracked stack for `OrgTwo/victim-repo`):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1 of body using OrgOne's known webhook_secret>

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgOne" },     // selects OrgOne's secret for verify_signature
    "full_name": "OrgTwo/victim-repo"    // actually used by PushHandler to resolve the stack
  }
}
```

`verify_signature` computes `Shipit.github(organization: "OrgOne")` and successfully verifies the signature with the attacker's own known secret [1](#0-0) . `PushHandler#process` then resolves `stacks` from `repository.full_name = "OrgTwo/victim-repo"` [4](#0-3)  and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack, despite the request never being authenticated for `OrgTwo`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
