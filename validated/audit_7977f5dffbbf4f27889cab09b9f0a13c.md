### Title
Webhook signature verification is bound to `repository.owner.login`, not to `repository.full_name` acted on by handlers, allowing cross-organization forgery of GitHub events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using a field taken directly from the untrusted JSON body (`repository.owner.login`), while every event `Handler` (which actually mutates state) resolves the target repository using a *different* field of the same body, `repository.full_name`. These two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and "the repository whose state is written" are two independently attacker-controlled values.

### Finding Description
`WebhooksController#verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This selects the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) purely from a body field that the requester supplies. In the "Using Multiple GitHub Applications" configuration, each organization owns its own distinct `webhook_secret` [2](#0-1) , and `Shipit.github(organization:)` looks the secret up per-organization key [3](#0-2) .

Once `verify_signature` passes, `WebhooksController#create` parses the body and dispatches it to handlers unchanged:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [4](#0-3) 

Every handler resolves the repository/stacks to act on via `Handler#repository_name`, which reads a **different** JSON key, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

The HMAC in `verify_webhook_signature` is computed over the entire raw request body [6](#0-5) , so an attacker cannot tamper with a legitimately-signed GitHub payload after the fact — but nothing prevents an attacker who legitimately knows/controls one organization's `webhook_secret` (e.g., they administer a GitHub App/organization "OrgA" that is also configured in the same Shipit instance) from **constructing their own POST body from scratch**, signing it with OrgA's secret, setting `repository.owner.login` = `"OrgA"` (so `verify_signature` passes) while setting `repository.full_name` = `"OrgB/victim-repo"` (an entirely unrelated organization/repository also hosted on the same Shipit instance). `verify_signature` only proves the body was signed by *someone who knows OrgA's secret*; it proves nothing about which repository `full_name` in that same body is legitimate, because GitHub never independently attests to a binding between `repository.owner.login` and `repository.full_name` from Shipit's point of view — the code just trusts both fields at face value from the same unauthenticated JSON blob under two different code paths.

This is precisely the class of bug reported for `UpliftOnlyExample`: a value that is checked (there, `maxAmountsIn`/fee math; here, `repository.owner.login` for signature routing) diverges from the value that is actually acted upon (there, the real `amountInRaw`; here, `repository.full_name` used to select which `Stack`/`Repository` gets updated).

### Impact Explanation
With cross-organization forgery of the `status` event (handled by `StatusHandler`), an attacker who legitimately controls OrgA's webhook secret can inject arbitrary commit statuses (`state: "success"`, arbitrary `context`) for **any commit SHA** onto **any repository/stack in OrgB**, since `StatusHandler#process` only filters by `Commit.where(sha: params.sha)` globally, without any repository scoping tied back to the verified organization:
```ruby
def process
  Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
end
``` [7](#0-6) 

Fabricated green CI statuses can satisfy deploy-gating checks (`ignore_ci`, required statuses) for a victim stack, enabling an unauthorized deploy of a commit that never actually passed CI on the real repository — i.e., undermining the integrity guarantee that gates deploys/merges. `PushHandler` similarly resolves stacks via `repository.full_name` and triggers `stack.sync_github(expected_head_sha:)` for the matched (victim) repository [8](#0-7) , letting a cross-org attacker force sync/refresh activity on repositories they do not own, and `CheckSuiteHandler` similarly cross-triggers `schedule_refresh_check_runs!` on a victim stack's commits [9](#0-8) .

### Likelihood Explanation
This requires the Shipit instance to be configured with multiple GitHub Apps/organizations (a documented, supported configuration) [2](#0-1) , and requires the attacker to be a legitimate admin of at least one of those configured organizations (so they know that organization's `webhook_secret`) while targeting a stack belonging to a different configured organization on the same instance. This is a realistic multi-tenant scenario for shared Shipit deployments serving several GitHub orgs, and requires no privileged Shipit account, `ApiClient` token, or GitHub App private key — only knowledge of one org's webhook secret, which the rules explicitly permit as an unprivileged-attacker starting point since it's a credential belonging to the attacker's own (legitimately controlled) organization, not the app's core secrets.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive the organization used for secret lookup from `repository.full_name` (the owner segment of the same field handlers use), or better, verify that `repository.owner.login` and the owner segment of `repository.full_name` match before dispatching to handlers. Additionally, `Handler#stacks`/`repository_name` should be scoped to (and cross-checked against) the organization whose secret produced a valid signature, rather than trusting an independent field from the same unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-administered, webhook secret known to attacker) and `OrgB` (victim, unrelated stack), per `docs/setup.md`'s "Using Multiple Github Applications" section.
2. Attacker crafts a raw JSON body for a `status` event:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` over this exact raw body using OrgA's known `webhook_secret`.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and successfully verifies the signature against OrgA's secret [10](#0-9) .
6. `StatusHandler#process` matches `Commit.where(sha: ...)` on the victim's commit (belonging to `OrgB/victim-repo`) and creates a forged "success" status on it [7](#0-6) , despite the request never being signed by, or associated with, OrgB.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
