### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but every event handler acts on the independently-attacker-controlled `repository.full_name` - allowing cross-repository/cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, read straight out of the untrusted, unparsed JSON body: `params.dig('repository', 'owner', 'login')`. [1](#0-0)  Once that check passes, `Handler#stacks`/`Handler#repository_name` looks up the target repository/stack using a *different* field from the same body, `payload.dig('repository', 'full_name')`. [2](#0-1)  Nothing binds these two fields together, and nothing in `verify_webhook_signature` covers which "organization" was used to select the secret - only the raw body bytes are HMAC-verified. [3](#0-2) 

### Finding Description
The binding that should hold is: `organization whose secret authenticated the request == organization owning the repository the handler mutates`. In a multi-tenant Shipit deployment (`config/secrets.yml` `github:` keyed by organization, as documented and implemented in `Shipit.github_app_config`/`Shipit.github`) [4](#0-3) , each organization can have its own, optional `webhook_secret`. [5](#0-4)  `GitHubApp#verify_webhook_signature` explicitly treats an unset secret as "always valid": `return true unless webhook_secret`. [6](#0-5) 

An attacker who can reach the `/webhooks` endpoint can:
1. Send a payload where `repository.owner.login` is any organization configured in this Shipit instance with no `webhook_secret` set (or any org whose secret the attacker happens to know, e.g. their own installation) - this is the value `verify_signature` uses to pick the `GitHubApp` and check the signature. [7](#0-6) 
2. Set `repository.full_name` in the very same payload to the full name of a completely different, victim repository/stack tracked by Shipit under a different organization.
3. Because the handlers never re-check that `repository.full_name`'s owner matches `repository_owner`, `Handler#repository_name` blindly resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and acts on it. [2](#0-1) 

Concretely, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack of the resolved (victim) repository matching the forged branch, using only fields from the forged body. [8](#0-7)  `PullRequest::ClosedHandler#process` similarly resolves the repository purely from `params.repository.full_name` and calls `review_stack.archive!`. [9](#0-8)  Neither handler ever consults `repository_owner`/the authenticating organization.

This is exactly the "organization authenticated vs. repository written" trust-binding break called out by the analog rules: the HMAC only certifies "this byte stream was sent by whoever configured organization X's secret" (or, when X has no secret, by anyone at all); it does not certify "and this stream only talks about organization X's repositories."

### Impact Explanation
An attacker can force unauthorized state changes on stacks/repositories they do not control, without any Shipit session, GitHub write access, or knowledge of the victim organization's `webhook_secret`:
- Forge `push` events to trigger `GithubSyncJob`/`stack.sync_github` against arbitrary tracked branches of a victim repository, corrupting Shipit's view of "latest deployed"/"deployable" commits (can be leveraged to make Shipit believe a malicious/rolled-back SHA is head, influencing what gets deployed).
- Forge `pull_request` closed events to archive a victim's review stacks.
- Forge `status`/`check_suite` events to inject fake commit statuses/check runs on a victim's commits, which several deploy-gating checks in Shipit rely on to decide deployability - directly threatening the "unauthorized deploy" impact bucket.
- Forge `membership` events to auto-create arbitrary teams/users under an org name of the attacker's choosing. [10](#0-9) 

This satisfies the "unauthorized deploy/rollback" and "cross-repository writes" impact classes without requiring any privileged credential from the victim.

### Likelihood Explanation
Requires only: (a) that this Shipit deployment is multi-tenant (`github:` keyed by multiple orgs - an officially supported and documented configuration), and (b) that at least one configured organization has no `webhook_secret` set (explicitly documented as "optional"), or that the attacker legitimately knows any one organization's secret from their own, unrelated app installation. Given webhook secrets are optional and multi-org configs are a first-class feature, this is a realistic deployment scenario, not a purely theoretical one. No rate-limiting, session, or GitHub write access is needed - a single unauthenticated POST to `/webhooks` suffices.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the target repository. Concretely, `WebhooksController#verify_signature` (or `Handler#repository_name`) should derive the organization strictly from `repository.full_name`'s owner segment (the same value the handler will act on), not from the separate `repository.owner.login`/`organization.login` field, and reject the request if these disagree. Alternatively, require `Repository.from_github_repo_name` lookups to also assert that the resolved repository's owner matches the organization whose secret validated the signature.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`: `victim-org` (with `webhook_secret: s3cr3t`) and `attacker-org` (no `webhook_secret`, i.e. omitted/nil), both plausible given the documented "optional" secret and multi-org schema. [11](#0-10) 
2. Shipit tracks a stack for `victim-org/service` with branch `main`.
3. Send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   (arbitrary/irrelevant)

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/service"
  }
}
```
4. `verify_signature` resolves `repository_owner = "attacker-org"`, whose `GitHubApp` has no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (bogus) `X-Hub-Signature` header. [6](#0-5) [7](#0-6) 
5. `PushHandler` resolves the repository from `full_name = "victim-org/service"` and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim's `main` stack. [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** config/secrets.development.example.yml (L18-29)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
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
