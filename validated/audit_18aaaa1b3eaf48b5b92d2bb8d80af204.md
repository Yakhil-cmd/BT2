This confirms a multi-tenant (multi-organization) Shipit deployment supports separate GitHub App configs per organization keyed by name, each with its own `webhook_secret`, resolved via `Shipit.github_app_config(organization)`. [1](#0-0) 

### Title
Webhook signature verified against `repository.owner.login`'s secret, but repository writes keyed off unvalidated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret to validate the HMAC signature using `repository.owner.login` (or `organization.login`) from the JSON payload. [2](#0-1) [3](#0-2)  However, once the signature check passes, every event handler resolves the target `Repository`/`Stack` from a *different* field in the same JSON body — `repository.full_name` — via `Handler#repository_name` / `Repository.from_github_repo_name`. [4](#0-3) [5](#0-4)  Nothing ties `repository.owner.login` to `repository.full_name`'s owner segment.

### Finding Description
In a multi-organization Shipit deployment, `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and its `webhook_secret`) per organization key in `secrets.github`. [1](#0-0)  An attacker who administers or is a collaborator on any organization/repo onboarded to the same Shipit instance (e.g., "attacker-org") knows or can obtain that organization's legitimate webhook delivery — thus can produce a validly-signed HMAC for a payload where `repository.owner.login` (or `organization.login`) is `"attacker-org"`. The `X-Hub-Signature` is only checked against the raw body using that org's secret; it does not bind the signature to the specific `repository.full_name` value semantically beyond it being byte-included in the signed body. Since `verify_signature` derives the app/secret purely from `repository.owner.login`, and the downstream handlers instead trust `repository.full_name` to select the `Stack`/`Repository` to mutate, an attacker can forge a JSON body whose `repository.owner.login` matches an org they control (to pass signature verification with their own known secret) while `repository.full_name` names a completely different, victim-owned repository (e.g., `"victim-org/victim-repo"`), since both fields are independently attacker-controlled in the JSON they submit and are never cross-validated. This breaks the equality binding: "organization authenticated by signature" == "organization owning the repository actually written."

Concretely, `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for any stack matching `repository.full_name`, and PR handlers call `ReviewStackAdapter#find_or_create!`, `archive!`, `unarchive!` on stacks/review-stacks resolved purely via `repository.full_name`. [6](#0-5) [7](#0-6) 

### Impact Explanation
This does not by itself grant RCE, credential exfiltration, or authentication bypass — it enables triggering repository sync/deploy-relevant side effects for a repository whose owner does not match the organization whose secret was used to sign the request. However, per the rules, valid impacts require concrete cross-repository writes leading to an unauthorized deploy/rollback/merge, or unauthenticated read of stack state. I could not confirm within the available context that `sync_github`, `find_or_create!`, `archive!`, or `unarchive!` alone perform a "write" strong enough to satisfy the Critical/High bar (e.g., they queue a `GithubSyncJob` to fetch/update commit state, not directly a deploy). Establishing whether this chain concretely leads to an unauthorized deploy, rollback, or merge would require tracing `Stack#sync_github` and `GithubSyncJob`, which I was not able to fully verify in the time available.

### Likelihood Explanation
Requires the attacker to control a legitimate organization/repository already onboarded onto the same shared Shipit instance (multi-tenant secrets.github configuration) — this is a real precondition in Shopify-style multi-org Shipit deployments, but is not "no privilege" in the strictest sense; it requires being a bona fide member of *some* onboarded org, not the victim org.

### Recommendation
Bind the value used to select the webhook-verification secret to the same value used to resolve the target repository — require `repository.owner.login` (used for signature selection) to match the owner segment of `repository.full_name` (used to resolve the `Repository`/`Stack`), and reject the webhook otherwise in `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb`) and/or in `Shipit::Webhooks::Handlers::Handler#repository_name`.

### Proof of Concept
1. Onboard/administer `attacker-org/some-repo` on the shared Shipit instance; know its webhook secret (as its GitHub App admin) so it can be configured to deliver correctly-signed webhooks.
2. Send `POST /webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with `attacker-org`'s secret over a body where:
   - `repository.owner.login = "attacker-org"` (used only for `verify_signature`)
   - `repository.full_name = "victim-org/victim-repo"` (used by `PushHandler`/`Repository.from_github_repo_name` to select the target stack)
3. `verify_signature` passes because it only checks the HMAC against `attacker-org`'s secret and `repository_owner` == `"attacker-org"`. [2](#0-1) 
4. `PushHandler#process` then looks up stacks for `victim-org/victim-repo` and calls `sync_github` on them, driven entirely by attacker-controlled `full_name`. [6](#0-5) 

**Note on confidence:** I was unable to fully trace `Stack#sync_github`, `GithubSyncJob`, and downstream deploy-triggering logic within the tool-call budget to confirm this chain reaches a Critical/High impact (unauthorized deploy/rollback/merge or cross-repo write) as strictly required by the rules. Without that confirmation, this should be treated as a real logic gap (broken authentication↔authorization binding) but of uncertain severity against the stated bar — a Devin session with fuller repo access should trace `app/models/shipit/stack.rb#sync_github` and `app/jobs/shipit/github_sync_job.rb` to determine if this reaches an unauthorized deploy/rollback/merge, which would upgrade this to a confirmed High/Critical finding.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
