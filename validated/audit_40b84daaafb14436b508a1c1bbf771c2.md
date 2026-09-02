### Title
Cross-organization webhook forgery bypasses repository binding – organization authenticated ≠ repository written ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body, then verifies the raw body against that organization's secret. Once verification succeeds, the event is dispatched to handlers that resolve the target `Stack`/`Repository` using a **different** field of the same unverified body: `repository.full_name` [1](#0-0) . Because verification only proves "whoever built this payload knows organization X's webhook secret," and never enforces that `repository.owner.login == full_name`'s owner, an attacker who controls (or has installed the Shipit GitHub App on) one organization can forge a payload whose `owner.login` is their own org (so it passes signature verification with their own known secret) while `repository.full_name` points at a completely different, victim organization's repository/stack tracked by the same Shipit instance.

### Finding Description
`verify_signature` in [2](#0-1)  computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it to pick the `GitHubApp`/secret via `Shipit.github(organization: repository_owner)` [3](#0-2) . Shipit explicitly supports one GitHub App (and one webhook secret) **per organization** [4](#0-3) .

After the signature is accepted, `Handler#stacks` resolves the target repository/stacks using an entirely different field of the same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`Repository.from_github_repo_name` splits this string into `owner/name` and looks up the tracked repository row directly, with no cross-check against `repository.owner.login` [5](#0-4) .

Equality that should hold but doesn't: **the organization whose secret authenticated the request == the owner of the repository that gets acted upon.** An attacker who controls organization `attacker-org` (with the Shipit App legitimately installed and its own webhook secret known to the attacker) can POST directly to `/webhooks` with a body where `repository.owner.login = "attacker-org"` (satisfies signature check) but `repository.full_name = "victim-org/victim-repo"` (drives the handler dispatch). The signature is computed over the raw body using `attacker-org`'s secret, which the attacker controls, so `verify_webhook_signature` succeeds [6](#0-5) .

Impact depends on the event/handler chosen:
- `push` (`PushHandler`) triggers `stack.sync_github(expected_head_sha: params.after)` for the victim's stacks [7](#0-6) , letting the attacker force resync/DoS retries and cache invalidation on a stack they don't own.
- `status` (`StatusHandler`) writes `Status` records directly from attacker-supplied fields (`target_url`, `state`, `description`, `context`, `created_at`) for **any commit SHA string** in the victim's repository, without any GitHub API round-trip to confirm the status actually came from GitHub for that repo, as shown by the controller test asserting the created `Status` fields are taken verbatim from the payload [8](#0-7) . Since Shipit deploy/merge gating relies on commit `Status`, an attacker who owns an unrelated organization can inject a fabricated "success" status for a commit in a completely different, victim-owned stack.

### Impact Explanation
This breaks the trust boundary between organizations that are each independently configured (and independently trusted only for their own repositories) in a multi-organization Shipit deployment. An actor who legitimately controls one organization's GitHub App installation can forge webhook events that are dispatched against a different organization's tracked stacks/repositories, injecting fake CI status (used to gate deploys) or forcing spurious sync/deploy-spec cache jobs on stacks they have no authorization over. Forged CI status directly threatens "an unauthorized deploy" since Shipit's deploy pipeline treats commit `Status` as a merge/deploy signal — this maps to the Critical impact category (unauthorized deploy) in scope.

### Likelihood Explanation
Requires the attacker to control (or otherwise obtain the webhook secret of) at least one GitHub organization onto which the shared Shipit instance's GitHub App is installed — a scenario explicitly documented as supported ("Using Multiple GitHub Applications") [9](#0-8) . No access to the victim organization, no Shipit session, and no API token is needed; only a POST to the public `/webhooks` endpoint with a self-signed body is required, matching the "unprivileged attacker" constraint.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, after signature verification, enforce that the organization used to select the webhook secret is the same organization that owns the repository being acted upon — e.g., derive `repository_owner` and compare it against the owner segment of `repository.full_name` (or better, resolve the target `Repository`/`Stack` first and confirm its stored `owner` matches the authenticating organization) before invoking any handler logic that mutates state for that repository.

### Proof of Concept
1. Deploy Shipit with the multi-organization GitHub App config (`config/secrets.yml` with `github: { attacker-org: {...}, victim-org: {...} }`), matching the documented setup [9](#0-8) .
2. Attacker knows `attacker-org`'s `webhook_secret` (they configured/installed that GitHub App themselves).
3. Attacker builds a `status` event JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "description": "forged",
  "context": "ci/forged",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and successfully verifies the signature [3](#0-2) .
6. `StatusHandler` resolves stacks via `repository.full_name = "victim-org/victim-repo"` [1](#0-0)  and creates/updates a `Status` on the victim's commit using attacker-controlled `state`/`target_url`/`description`, even though the attacker has no relationship to `victim-org`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
