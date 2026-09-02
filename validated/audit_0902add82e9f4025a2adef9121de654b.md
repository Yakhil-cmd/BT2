### Title
Cross-organization webhook impersonation via mismatched `repository.owner.login` vs `repository.full_name` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, the incoming webhook's HMAC signature is verified against the GitHub App secret selected from `repository.owner.login` (or `organization.login`), while every event handler resolves the actual target `Repository`/`Stack` using the independent `repository.full_name` field from the same attacker-suppliable JSON body. Because these two fields are never cross-checked, an attacker who legitimately controls one onboarded organization (and therefore knows that organization's own `webhook_secret`) can forge a correctly-signed webhook whose "owner" field selects their own org's secret but whose "full_name" field targets a repository belonging to a completely different, victim organization hosted on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to validate the request against using: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted request body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` looks up the per-organization config populated from `secrets.yml`, exactly as documented for multi-org setups: [3](#0-2) [4](#0-3) 

Once the signature check passes (using the org selected by `repository.owner.login`), `WebhooksController#create` hands the *same raw JSON* to every registered handler: [5](#0-4) 

Every handler resolves the actual `Repository`/`Stack` to act on via a *different* field, `repository.full_name`, with no re-validation that it matches the organization whose secret authenticated the request: [6](#0-5) 

This pattern repeats in every pull_request handler (`opened_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `closed_handler.rb`, `label_capturing_handler.rb`), all of which do `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and then act on that repository's `ReviewStack`s: [7](#0-6) 

This is structurally identical to the reported Babylon flaw: the field that is cryptographically "covered"/relied-upon for trust (the organization used to select the verifying secret) is not the same field that downstream logic actually consumes to decide *what gets mutated* (the target repository/stack). An attacker who is a legitimate administrator of `OrgAttacker` (and therefore knows `OrgAttacker`'s own `webhook_secret`, which they themselves configured when creating their GitHub App) can POST directly to `/webhooks` with:

```json
{
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgVictim/critical-repo" },
  ...
}
```

signed with `OrgAttacker`'s secret. `verify_signature` succeeds (because it only looks at `owner.login`), yet the handler resolves and mutates state for `OrgVictim/critical-repo`, using `Shipit.github(organization: repository.owner)` (i.e. `OrgVictim`'s real GitHub App/token) whenever it needs to talk back to GitHub, e.g. `Stack#github_app`: [8](#0-7) 

### Impact Explanation
By crafting `pull_request` `opened`/`labeled`/`reopened`/`unlabeled` events targeting `OrgVictim/critical-repo`, the attacker can create or unarchive a `ReviewStack` whose `branch` is taken directly from attacker-controlled `pull_request.head.ref`: [9](#0-8) 

Once created/unarchived, the stack is queued for provisioning and later deployed using `OrgVictim`'s real GitHub App credentials (`Stack#github_app`/`#github_api`), executing whatever `shipit.yml` exists on the attacker-chosen branch/ref of `OrgVictim`'s repository, on the shared deploy host, against `OrgVictim`'s repository. This is an unauthorized deploy/provision on a repository the attacker does not control, using the credentials of an unrelated organization, i.e. exactly "an unauthorized deploy" / "cross-repository writes" as defined in scope, satisfying the Critical/High bar.

`status`/`check_suite`/`push` handlers are similarly exploitable to inject fake commit statuses or trigger syncs against the victim repository's tracked commits/stacks, further undermining CI-gated deploy decisions.

### Likelihood Explanation
This requires the attacker to control at least one organization/GitHub App that a shared Shipit instance has legitimately onboarded (a documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications"), and to know that organization's own webhook secret, which they set themselves. No access to Shipit sessions, `ApiClient` tokens, or the victim org's secrets is required. Any organization admin onboarded to a shared multi-tenant Shipit instance can mount this attack against every other tenant on the same instance, purely by crafting an HTTP POST to `/webhooks`.

### Recommendation
In `Handler#repository_name` (and any place that resolves the target repository/stack from the payload), require that the organization portion of `repository.full_name` (or `repository.owner.login`) matches the organization actually used to authenticate the webhook (`repository_owner` computed in `WebhooksController`), rejecting/discarding events where they diverge. Alternatively, pass the authenticated `repository_owner` explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` and have `Handler#stacks`/`#repository` scope lookups to `Repository.where(owner: authenticated_owner).from_github_repo_name(...)` rather than trusting `full_name` in isolation.

### Proof of Concept
1. Configure a shared Shipit instance with two organizations in `secrets.yml`, e.g. `OrgAttacker` and `OrgVictim`, each with review stacks / `allow_all` provisioning enabled for a repo (as in `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml` multi-org schema).
2. As the administrator of `OrgAttacker`, know `OrgAttacker`'s `webhook_secret` (set when creating the App).
3. Build a `pull_request` `opened` payload:
   ```json
   {
     "action": "opened",
     "number": 999,
     "pull_request": {
       "id": 1, "number": 999, "url": "...", "title": "x", "state": "open",
       "additions": 0, "deletions": 0,
       "head": { "sha": "deadbeef", "ref": "malicious-branch" },
       "user": { "login": "attacker" },
       "assignees": [], "labels": []
     },
     "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgVictim/critical-repo" },
     "sender": { "login": "attacker" }
   }
   ```
4. Compute `X-Hub-Signature: sha1=HMAC_SHA1(OrgAttacker_webhook_secret, body)` and POST to `/webhooks` with `X-Github-Event: pull_request`.
5. `WebhooksController#verify_signature` uses `Shipit.github(organization: "OrgAttacker")` and succeeds.
6. `OpenedHandler` resolves `Shipit::Repository.from_github_repo_name("OrgVictim/critical-repo")` and, if provisioning is `allow_all`, creates a `ReviewStack` with `branch: "malicious-branch"` on `OrgVictim`'s repository, which is subsequently provisioned/deployed using `OrgVictim`'s GitHub App credentials.

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

**File:** app/models/shipit/stack.rb (L434-440)
```ruby
    def github_api
      github_app.api
    end

    def github_app
      Shipit.github(organization: repository.owner)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
