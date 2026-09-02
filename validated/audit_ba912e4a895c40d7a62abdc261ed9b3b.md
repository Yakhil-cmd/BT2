### Title
Cross-organization webhook forgery: signature verification authenticates the payload's `repository.owner`/`organization` org, but write handlers (e.g. `StatusHandler`, `PushHandler`) act on unrelated payload fields (`repository.full_name`, `sha`) that are never bound to that org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using only `repository.owner.login` (or `organization.login`) from the untrusted JSON body, then hands the *entire* parsed body to the matching event handler. In a multi-organization Shipit deployment (an officially documented and supported configuration), each organization has its own independent `webhook_secret`. Nothing ties the specific repository/commit that a handler subsequently *acts on* to the organization whose secret validated the request. An attacker who legitimately controls one onboarded organization's GitHub App (and therefore knows/can rotate that org's own `webhook_secret`) can produce a validly-signed request for their own org while embedding a `repository.full_name` or `sha` belonging to a completely different, unrelated organization/stack, causing writes against that victim stack.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the secret) purely from the request body itself: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple GitHub Apps, one per organization, each with its own independent `webhook_secret`: [3](#0-2) [4](#0-3) 

Once `verify_signature` passes (using the secret tied to whatever org the attacker declared in `repository.owner.login`), `WebhooksController#create` dispatches the *entire* body to the handler for the event type, with no re-validation that the repository/commit referenced inside actually belongs to that organization: [5](#0-4) 

Handlers then trust arbitrary identifying fields from the payload to select what to mutate. `StatusHandler` is the clearest case: it looks up commits **by `sha` alone, globally, with zero repository/organization scoping**, and writes a new status onto them: [6](#0-5) 

`PushHandler` similarly resolves the target purely from `repository.full_name` in the same signed-but-uncorrelated body: [7](#0-6) [8](#0-7) 

The equality this breaks is: `organization whose secret validated the HMAC` should equal `organization owning the repository/commit the handler mutates`. Because both the organization-selector field (`repository.owner.login`) and the target-selector fields (`repository.full_name`, `sha`) live in the same attacker-controlled JSON body, and the HMAC only proves "some org's app signed this exact byte string," an attacker who owns one org's GitHub App secret can freely mismatch these two fields.

### Impact Explanation
An organization operator onboarded into a shared, multi-org Shipit instance (someone who legitimately administers their own org's GitHub App and therefore its `webhook_secret`) can:
- Forge a `push` webhook that is "authenticated" as their own org but whose `repository.full_name` targets a stack belonging to a completely different tenant org, triggering `stack.sync_github` on that victim stack.
- Forge a `status` webhook, signed with their own org's secret, that injects a fabricated commit status (`success`/`failure`, arbitrary `description`/`target_url`) onto *any* commit SHA in the entire installation — including commits belonging to a victim organization's stack — since `Commit.where(sha:)` performs no ownership check at all.

Because Shipit gates merges and deploys on commit statuses/checks, this enables writes (and potential unauthorized-deploy conditions) against a repository/stack the attacker has no GitHub permission on whatsoever — a cross-repository, cross-tenant write achieved purely by exploiting the mismatch between the field used for HMAC-org-selection and the fields used for target-selection. This lands squarely in the "cross-repository writes" / "unauthorized deploy" Critical bucket.

### Likelihood Explanation
Requires only that the target Shipit deployment be configured for multiple organizations (a first-class, documented Shipit feature — `test/dummy/config/secrets_double_github_app.yml`, `docs/setup.md`) and that the attacker be a legitimate administrator/owner of at least one onboarded org (i.e., they know their own org's `webhook_secret`, which they set themselves in their own GitHub App settings — not a Shipit secret, not privileged Shipit access). No Shipit account, `ApiClient` token, or GitHub write access to the victim repository is required. The only extra step is crafting a raw JSON body with a mismatched `repository`/`sha` and computing the HMAC with their own known secret, which is straightforward.

### Recommendation
After selecting the `GitHubApp` via `repository_owner` and verifying the HMAC, re-validate that every organization-identifying field actually used by the dispatched handler (`repository.full_name`'s owner segment, and for `status` events, the owning repository of the resolved `Commit`) matches the `repository_owner` that was used to select the signing secret. Concretely: pass the verified `repository_owner`/organization into `Shipit::Webhooks.for_event` and have each handler (especially `StatusHandler`) scope its lookup (`Commit.where(sha:, stack: { repository: { owner: verified_org } })`) instead of trusting `repository.full_name`/`sha` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s "Using Multiple Github Applications" section) — this is the standard supported multi-tenant setup.
2. As the legitimate administrator of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret` (you set/own it).
3. Craft a `status` event JSON body:
```json
{
  "sha": "<commit sha belonging to OrgB's stack>",
  "state": "success",
  "description": "forged",
  "repository": { "owner": { "login": "OrgA" } }
}
```
4. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POST to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` → `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully (see `lib/shipit/github_app.rb#verify_webhook_signature`).
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no organization scoping (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) and writes a forged "success" status onto the OrgB commit — despite the attacker having no relationship to OrgB whatsoever.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
