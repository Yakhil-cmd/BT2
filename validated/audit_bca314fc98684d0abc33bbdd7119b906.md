### Title
Webhook signature verified against the payload's claimed organization, but statuses/syncs are written to commits/repos identified by unchecked payload fields, enabling cross-org status forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate against based on an attacker-controlled JSON field (`repository.owner.login`, or fallback `organization.login`), then verifies the signature over the raw body using that org's secret. Once verification passes, the event `params` (the same untrusted JSON body) are handed to the registered handler, which acts on data pulled from *other* fields of that same body that are never cross-checked against the org that was actually authenticated. This breaks the equality: "organization whose secret authenticated this request" == "repository/commit that is written by the handler."

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to pick which per-organization `webhook_secret` to validate the signature with: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple GitHub organizations, each with its own independently configured `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature check passes (because the request was signed with *some* org's correct secret), the entire raw body — not just the `repository.owner`/`organization` sub-object used to pick the secret — is dispatched to handlers as trusted `params`: [5](#0-4) 

The `status` handler is the clearest instantiation of the broken binding: it looks up `Commit` **globally by `sha`**, with no scoping to the repository/organization that authenticated the request, and writes an attacker-supplied `state`/`description`/`target_url`/`context` directly onto it: [6](#0-5) 

That status directly feeds CI-gating logic used for both deploy eligibility and PR auto-merge decisions: [7](#0-6) [8](#0-7) 

Similarly, other handlers (`PushHandler`, `CheckSuiteHandler`, pull-request handlers, `Handler#stacks`) resolve the target `Stack`/`Repository` via `payload.dig('repository', 'full_name')`, a field that is never validated to match the `repository.owner.login` field used for secret selection: [9](#0-8) [10](#0-9) [11](#0-10) 

This is structurally identical to the `concat` bug class: a "buffer" (here, the trust boundary established by signature verification) is allocated/checked against one index (`repository.owner.login`), while writes actually occur at an offset defined by a different, unchecked value (`repository.full_name` / `sha`) inside the same attacker-controlled structure — the check and the write are not bound to the same field.

### Impact Explanation
Whoever legitimately controls the webhook secret for *any one* organization configured in a multi-org Shipit deployment (e.g., an org admin who installed their own GitHub App and set its `webhook_secret`) can forge a signed `status` event whose `sha` matches a commit belonging to an *entirely different, unrelated org/repo* tracked by the same Shipit instance. Because `StatusHandler` resolves the target commit by a global `Commit.where(sha:)` lookup with no org/repo scoping, the attacker can set `state: 'success'` on any commit's status. Since `Commit#deployable?` and `MergeRequest#any_status_checks_failed?`/`#all_status_checks_passed?` both key off these very status rows, this can cause an unauthorized deploy or an unauthorized PR auto-merge for a repository the attacker has no legitimate relationship with — matching the "High"/"Critical" impact bar of "an unauthorized deploy, rollback, or merge" / "cross-repository writes."

### Likelihood Explanation
This requires the attacker to control the webhook secret of at least one org already onboarded to the shared Shipit instance — a realistic scenario for any Shipit deployment serving multiple organizations/teams with per-org GitHub Apps, since each org's admin independently sets their own `webhook_secret` and none of them is meant to be trusted with write access to other orgs' repos. The only additional requirement is guessing/knowing a target commit SHA for another tracked repo, which is public information on GitHub. No privileged Shipit session, `ApiClient` token, or GitHub App private key is required — only the webhook secret of one's own onboarded org.

### Recommendation
Bind the field used for signature-secret selection to the fields later trusted by handlers: after selecting the org's secret and verifying the signature, re-validate that `repository.owner.login` (or `organization.login`) matches the owner segment of `repository.full_name` before dispatching to handlers, and scope `StatusHandler`'s `Commit` lookup (and other handlers' repository resolution) to repositories belonging to the verified organization rather than a global, unscoped lookup.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema), both syncing repos/stacks into the same Shipit instance.
2. As the (legitimate) admin of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret`.
3. Find a commit SHA of a tracked `OrgB` repository whose CI has not yet reported success (e.g., a pending PR commit).
4. Craft a `status` event JSON body:
```json
{
  "sha": "<OrgB commit sha>",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "OrgA" } }
}
```
5. Sign the raw body with `OrgA`'s `webhook_secret` (`sha1=` HMAC) and POST it to `/webhooks` with header `X-Github-Event: status`.
6. `verify_signature` picks `Shipit.github(organization: 'OrgA')` (from `repository.owner.login`), verifies successfully against `OrgA`'s secret.
7. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `OrgB` commit — and calls `commit.create_status_from_github!(params)`, writing `state: success` regardless of the fact the request was authenticated for `OrgA`.
8. `OrgB`'s commit now reports as `deployable?`/merge-eligible, even though nothing about the forged request was ever authenticated for `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
