### Title
Webhook signature verified against `repository.owner.login`, but handlers act on the unverified `repository.full_name` field — cross-organization webhook forgery in multi-tenant deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, derived only from `params.dig('repository', 'owner', 'login')` (or `organization.login`): [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple, independently-configured GitHub Apps, one per organization, each with its own distinct `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `Shipit::Webhooks.for_event(event)` dispatches the raw payload to handlers such as `PushHandler`, `PullRequest::OpenedHandler`, etc. These handlers determine *which* `Repository`/`Stack` to act on using a **different** field of the same payload: `payload.dig('repository', 'full_name')`, via `Handler#repository_name` / `Handler#stacks`: [5](#0-4) [6](#0-5) 

The `repository.owner.login` field (used for signature-key selection) and `repository.full_name` field (used to select the target `Repository`/`Stack` to write to) are never cross-checked against each other. This is exactly the bug class from the referenced report: a value used for a safety/validation calculation (`updatedTotalSupply` clamped to `MAX_SUPPLY`) diverges from the value actually consumed downstream (`_profit` still uses the pre-clamp number) — here, the field used to *authenticate* the payload (`repository.owner.login`) diverges from the field used to *act* on the payload (`repository.full_name`).

The binding that should hold is:
```
organization whose webhook_secret validated the signature == organization that owns the repository being acted upon
```
This binding is never enforced.

### Impact Explanation
An attacker who legitimately administers (or has compromised) the GitHub App/webhook configuration for **one** organization onboarded to a shared Shipit instance (`OrgA`, knows `OrgA`'s `webhook_secret`) can POST directly to `/webhooks` with a crafted JSON body where:
- `repository.owner.login = "OrgA"` / `organization.login = "OrgA"` (so `verify_signature` picks `OrgA`'s `GitHubApp` and the attacker computes a valid HMAC with the secret they know), and
- `repository.full_name = "OrgB/target-repo"` (a completely unrelated org's repository that Shipit also manages).

Because `Handler#stacks` / `Handler#repository_name` only look at `repository.full_name`, the forged event is processed against `OrgB`'s `Repository`/`Stack` records — despite the signature never having been validated with `OrgB`'s secret. For the `push` event this triggers `stack.sync_github(expected_head_sha: params.after)` on `OrgB`'s stack, which can advance Shipit's view of `OrgB`'s branch head and, when `continuous_deployment?` is enabled, trigger `Stack#trigger_continuous_delivery` → `trigger_deploy`, i.e. an **unauthorized deploy** of `OrgB`'s stack initiated purely by an operator who only controls `OrgA`'s webhook credentials: [7](#0-6) [8](#0-7) 

Other handlers (`PullRequest::OpenedHandler`, `LabeledHandler`, etc.) are equally affected: they resolve the acted-upon repository via `params.repository.full_name` with no organization cross-check, allowing cross-tenant creation/archiving of review stacks.

This satisfies the required impact bar of "unauthorized deploy" / cross-repository writes, and matches the required binding category: "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Requires the operator to run Shipit in the documented multi-GitHub-App configuration (one org per attacker-accessible webhook secret) and for the attacker to control a legitimate (or previously compromised) GitHub App/webhook secret for at least one onboarded organization — a realistic scenario for any Shipit instance shared across independent teams/orgs, which is the entire purpose of the documented multi-app feature. No `ApiClient` token, session, or GitHub write access to the *target* repo is needed; only knowledge of one organization's `webhook_secret`, which the engine's own multi-tenant design deliberately hands out per-organization.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), require that the organization/app whose secret validated the signature matches the owner of the repository the handler is about to act on. Concretely: pass the verified `repository_owner` into `Handler.call`/`Handler#initialize`, and in `Handler#repository_name`/`#stacks`, assert `payload.dig('repository','owner','login')&.casecmp?(verified_organization)` before resolving/mutating any `Repository`/`Stack`, rejecting (422) on mismatch.

### Proof of Concept
1. Shipit configured with two organizations, `OrgA` and `OrgB`, each with a distinct GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker knows `OrgA`'s `webhook_secret` (e.g., they are a legitimate admin of `OrgA`'s GitHub App).
3. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha_that_exists_in_OrgB/target-repo>",
  "repository": { "full_name": "OrgB/target-repo", "owner": { "login": "OrgA" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository_owner`), verifies successfully since the attacker used `OrgA`'s real secret.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/target-repo")`, and calls `stack.sync_github(expected_head_sha: ...)` on `OrgB`'s stack — an action the attacker could not have authenticated for `OrgB` — potentially triggering an unauthorized deploy if `OrgB`'s stack has continuous deployment enabled.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
