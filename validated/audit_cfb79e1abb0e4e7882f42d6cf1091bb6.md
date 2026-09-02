### Title
Webhook signature verification authenticates the GitHub organization named in an attacker-controlled JSON field, while all downstream event handlers resolve the target repository/stack from a *different*, independently-controlled field of the same unauthenticated payload — allowing cross-organization / cross-repository event forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a webhook against using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . Every event handler, however, resolves the actual `Repository`/`Stack` that the event will be applied to using `payload.dig('repository', 'full_name')` [3](#0-2) . Both `repository.owner.login` and `repository.full_name` are independent, attacker-supplied fields inside the same JSON body that arrives over an unauthenticated HTTP endpoint before signature verification runs. Because the HMAC check only proves the sender knows the secret belonging to whatever organization `repository.owner.login` names, and never re-validates that this organization actually owns the repository identified by `repository.full_name`, an operator running Shipit for multiple GitHub organizations (a supported, documented configuration — see `test/dummy/config/secrets_double_github_app.yml` and `Shipit.github_organizations`/`github_app_config` in `lib/shipit.rb`) can forge webhook events against repositories belonging to a different organization than the one whose secret they used.

### Finding Description
The engine explicitly supports multi-organization GitHub App configuration: `Shipit.github(organization:)` looks up a per-organization config block and instantiates a `GitHubApp` with that organization's own `webhook_secret` [4](#0-3) .

The signature check is:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
head(422) unless verified
``` [2](#0-1) 

`repository_owner` is taken straight from the untrusted JSON body:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This value only decides *which secret* is used to compute the expected HMAC — it proves the sender knows one organization's secret, nothing about the repository the event claims to describe.

Once verification passes, every registered handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`, `MembershipHandler`, listed in `Shipit::Webhooks.default_handlers`) [5](#0-4)  independently determines the target repository from a *different* JSON path:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`repository.owner.login` (used for authentication) and `repository.full_name` (used to select the write target via `Repository.from_github_repo_name`) are two separate keys of the same attacker-controlled `repository` object — nothing forces them to describe the same repository. An attacker who is a legitimate member of Organization A (and therefore knows Organization A's `webhook_secret`, or targets an Organization A entry configured with a blank `webhook_secret`, which `verify_webhook_signature` treats as "always verified": `return true unless webhook_secret` [7](#0-6) ) can submit a payload where:
- `repository.owner.login` = `"org-a"` (used only to pick the signing key, satisfied)
- `repository.full_name` = `"org-b/victim-repo"` (used by every handler to look up the actual `Stack`/`Repository` to act on)

The binding that should hold — `organization that authenticated == organization owning the repository being written` — is broken.

### Impact Explanation
Concretely, `StatusHandler` maps webhook fields (`sha`, `state`, `target_url`, `description`, `context`, `created_at`) directly onto a `Commit::Status` for whichever commit/stack `repository.full_name` resolves to, as exercised in `webhooks_controller_test.rb` [8](#0-7) . Since Shipit's continuous-deployment/merge-queue logic gates automatic deploys and merges on commit CI status, an attacker who only controls a secondary, unrelated organization onboarded to the same Shipit instance can forge a passing status for a commit on a completely different organization's tracked repository/stack, triggering an **unauthorized deploy** (or unblocking a merge) — a Critical-tier impact per the engine's own severity classes ("an unauthorized deploy, rollback or merge"). Other handlers (`push`, `pull_request`, `check_suite`, `membership`) are similarly reachable cross-organization once the authentication/target-repository binding is broken, expanding the blast radius to spurious sync jobs, membership/team churn, and PR-state manipulation on repositories outside the attacker's authenticated org.

### Likelihood Explanation
This requires the host to configure more than one GitHub organization against a single Shipit instance (a supported and documented deployment mode, evidenced by `test/dummy/config/secrets_double_github_app.yml`), and the attacker to control (or have push/webhook access to) at least one of those organizations — a realistic scenario for shared/multi-tenant Shipit deployments serving several GitHub orgs. No GitHub App private key, `api_clients_secret`, or privileged Shipit account is needed; only the attacker's own organization's webhook secret (which they legitimately possess) or one org left with an unset `webhook_secret`.

### Recommendation
After resolving `repository.full_name` to a `Repository`/`Stack` inside each handler, verify that the resolved repository's owner actually matches the `repository_owner` (or `organization`) that was cryptographically authenticated in `WebhooksController#verify_signature`, and reject/drop the event otherwise. Alternatively, derive `repository_owner` for signature-key selection from the same authoritative source used for repository resolution (i.e., bind the HMAC-selection key and the write-target key to a single, immutable payload path) so the two can never diverge.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `org-a` and `org-b`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), and a tracked stack for `org-b/victim-repo`.
2. As a member of `org-a`, compute a valid HMAC-SHA1 signature for the following JSON body using `org-a`'s `webhook_secret`:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests",
  "description": "forged",
  "target_url": "https://ci.example.com/forged",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. `POST /github/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` selects `Shipit.github(organization: "org-a")` and validates successfully against `org-a`'s secret [9](#0-8) .
5. `StatusHandler` (via `Handler#repository_name` = `"org-b/victim-repo"`) resolves the victim `Stack` and creates a forged passing `Commit::Status`, even though the attacker was never authenticated for `org-b` [3](#0-2) .

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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
