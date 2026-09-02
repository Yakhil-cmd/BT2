### Title
Webhook signature is verified against the wrong GitHub organization's secret, letting a rogue org holder forge cross-repository webhook events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using an attacker-controlled field of the very payload being validated (`repository.owner.login`, falling back to `organization.login`), while the handlers that act on the payload use a *different* attacker-controlled field (`repository.full_name`) to decide which `Repository`/`Stack` to mutate. In a multi-organization Shipit deployment, this breaks the binding "organization whose secret authenticated the request == repository the request is allowed to act on."

### Finding Description
`verify_signature` computes the org to authenticate against solely from the request body: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up the per-organization `webhook_secret` from `config/secrets.yml` when Shipit is configured for multiple GitHub organizations (a documented, supported feature): [2](#0-1)  and `docs/setup.md`'s "Using Multiple Github Applications" section.

`verify_webhook_signature` then HMACs the *entire* raw body with that org's secret: [3](#0-2) .

Crucially, nothing ties the org used to select the secret (`repository.owner.login`) to the repository the event handlers actually operate on. Handlers derive the target repository from a separate JSON field, `repository.full_name`: [4](#0-3) 

and downstream handlers such as `PushHandler`, `StatusHandler`, and the `PullRequest::*Handler`s use that value/derived commit shas to locate `Stack`/`Repository`/`Commit`/`PullRequest` records and mutate them: [5](#0-4) [6](#0-5) [7](#0-6) 

Because `repository.owner.login` and `repository.full_name` are two independent fields inside the same signed JSON body, an attacker who legitimately owns/administers a GitHub organization ("orgA") already onboarded to the Shipit instance knows orgA's `webhook_secret` (they configured the GitHub App themselves). They can craft a JSON body where `repository.owner.login = "orgA"` (so `verify_signature` selects orgA's secret and the HMAC matches) but `repository.full_name = "orgB/target-repo"` (a different organization's repository also tracked by the same Shipit instance). The signature check passes because it is only proving "signed by someone who knows orgA's secret," not "this is a legitimate event about orgA's repositories."

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out in scope. Concretely, with a forged, correctly-"verified" webhook an attacker can:
- Trigger `PushHandler` → `stack.sync_github(expected_head_sha:)` for a victim stack/repo they don't own [5](#0-4) .
- Inject a forged commit `status` (`state: success`, arbitrary `context`) onto a victim's commit via `StatusHandler` → `Commit#create_status_from_github!`, which can satisfy `ci.require` checks used by Shipit's merge queue/deploy gating [6](#0-5) .
- Archive/close review stacks or otherwise mutate `PullRequest`/`ReviewStack` state for a victim repository via the `PullRequest::*Handler`s [8](#0-7) .

Forged, falsely-verified CI status can gate an unauthorized deploy or merge on the victim stack, which maps to the in-scope "Critical: unauthorized deploy, rollback or merge" outcome.

### Likelihood Explanation
Requires the Shipit instance to be configured with more than one GitHub organization (the documented "Using Multiple Github Applications" mode) and that the attacker owns/administers at least one of those organizations' GitHub Apps (so they can read their own `webhook_secret`) — no Shipit session, `ApiClient` token, or victim-repo access is needed, satisfying the "unprivileged attacker" constraint. This is a realistic configuration since Shipit explicitly supports and documents multi-org setups for this exact scenario (e.g., a company hosting deploys for multiple GitHub orgs from one Shipit instance).

### Recommendation
Bind signature verification to the same repository identity the handlers use to act, not to an independently-controlled field:
- Verify the signature using the secret associated with `repository.full_name` (or the resolved `Repository`/`Stack`'s configured organization), not `repository.owner.login`/`organization.login` read in isolation.
- After computing `repository_owner`, cross-check that it matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting mismatches with 422.
- Alternatively, resolve the target `Repository` record first (independently of any org field in the payload) and verify the signature using that repository's associated organization's secret exclusively.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config).
2. As an attacker who administers `orgA`'s GitHub App, read `orgA`'s `webhook_secret` from the App's own settings.
3. Build a `push` (or `status`) webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>`.
5. POST the body with header `X-Github-Event: push` to `/webhooks`.
6. `verify_signature` resolves `Shipit.github(organization: "orgA")`, validates the HMAC against `orgA`'s secret — passes.
7. `PushHandler` resolves the target stack via `repository.full_name = "orgB/target-repo"` (unrelated to `orgA`) and triggers `stack.sync_github` on the victim `orgB` repo, despite the request never being authenticated by `orgB`'s credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
