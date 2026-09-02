Confirmed root cause: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [1](#0-0)  to look up the target `Repository`/`Stack` via `Repository.from_github_repo_name` [2](#0-1) , while `WebhooksController#verify_signature` selects which GitHub App/webhook secret authenticates the request using a *different* field, `params.dig('repository', 'owner', 'login')` (or `organization.login`) [3](#0-2) [4](#0-3) . Since the entire JSON body is attacker-controlled and these two fields (`repository.owner.login` vs `repository.full_name`) are never cross-checked, an attacker can pick `owner.login` = an org whose webhook secret they know, while setting `full_name` = "victim-org/victim-repo" to make handlers act on a stack belonging to a different, unauthenticated organization.

### Title
Cross-organization write via webhook: signature validated against `repository.owner.login`, but handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` computes the HMAC-verifying `GitHubApp` (and thus which per-organization `webhook_secret` is used) from `repository.owner.login` (falling back to `organization.login`) taken directly out of the untrusted, attacker-supplied JSON body [5](#0-4) . Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers on the same raw `params` hash [6](#0-5) . All handlers resolve the target repository/stack via `Shipit::Webhooks::Handlers::Handler#repository_name`, which reads `payload.dig('repository', 'full_name')`, an entirely separate key from the one used for signature-org selection [7](#0-6) . Nothing in the code enforces that `repository.owner.login` and `repository.full_name`'s owner segment refer to the same GitHub org.

### Finding Description
In a multi-tenant Shipit install (documented in `docs/setup.md` "Using Multiple Github Applications" and `lib/shipit.rb#github`/`#github_app_config`), each GitHub organization has its own `webhook_secret` [8](#0-7) . The binding the protocol depends on is: "the organization whose secret authenticated this webhook" == "the organization/repository the handler is permitted to mutate." That equality is never enforced.

- `verify_signature` picks the verifying `GitHubApp`/secret using `repository_owner`, computed from `params.dig('repository','owner','login')` [4](#0-3) .
- `verify_webhook_signature` HMACs the entire raw body against that org's secret [9](#0-8) . This only proves the payload was signed by whoever holds *that one org's* secret - it does not constrain any individual field's semantic content.
- Downstream, `Handler#stacks`/`#repository_name` look up the affected `Repository` using `payload.dig('repository', 'full_name')` [10](#0-9) , and `Repository.from_github_repo_name` splits that string on `/` to find the DB row by `owner`/`name` [2](#0-1) .

Because `owner.login` and `full_name` are independent, attacker-controlled JSON keys with no GitHub-side consistency check performed by Shipit, an attacker who has (or leaks/guesses) the webhook secret for one onboarded organization ("OrgA") can craft:
```json
{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgVictim/target-repo", "name": "target-repo"}, "ref": "refs/heads/main", "after": "<attacker sha>"}
```
sign it with OrgA's secret, and have `PushHandler` (or any other handler) resolve and mutate stacks belonging to `OrgVictim`, an organization for which the attacker holds no credential at all.

### Impact Explanation
This is a cross-repository/cross-organization write: an unauthorized `push`/`status`/`pull_request` webhook can be routed to mutate a `Stack` under an organization the attacker was never authenticated for, e.g. triggering `stack.sync_github(expected_head_sha:)` on an arbitrary victim repo's stack via `PushHandler#process` [11](#0-10) , or forging commit statuses via `StatusHandler#process` [12](#0-11) . This matches the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Requires the attacker to already possess at least one onboarded organization's `webhook_secret` (their own org's, if they are a legitimate tenant/admin of one org in a shared multi-tenant Shipit instance) but none for the victim org — a realistic scenario for shared/multi-org Shipit deployments where different teams each control one org's GitHub App config. No repository write access, session, or `ApiClient` token is needed on the victim side.

### Recommendation
After signature verification selects the organization (`repository_owner`), re-derive/validate the target repository strictly against that same verified organization, e.g., require `payload.dig('repository','full_name')` to start with `"#{verified_organization}/"` before dispatching to handlers, or have `Handler#repository_name`/`#stacks` be scoped by the verified organization passed down from the controller rather than re-parsed independently from `full_name`.

### Proof of Concept
1. Configure two organizations, `OrgA` and `OrgVictim`, each with distinct `webhook_secret`s, as in `test/dummy/config/secrets_double_github_app.yml` [13](#0-12) .
2. As an attacker who only knows `OrgA`'s `webhook_secret`, build a push payload:
```json
{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgVictim/target-repo", "name": "target-repo"},
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
3. Compute `X-Hub-Signature` as `sha1=` + HMAC-SHA1(OrgA's webhook_secret, raw body).
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` selects `Shipit.github(organization: 'OrgA')`, verifies successfully against OrgA's secret [3](#0-2) , then `PushHandler` resolves `Repository.from_github_repo_name('orgvictim/target-repo')` [10](#0-9)  and calls `stack.sync_github` on OrgVictim's stack — despite the attacker never holding OrgVictim's webhook secret.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-17)
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
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
```
