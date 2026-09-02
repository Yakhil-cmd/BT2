## Vulnerability Found

### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, but the repository actually written to is selected from the unrelated `repository.full_name` field, allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, derived from the payload's `repository.owner.login` (or `organization.login`) field. Every webhook handler, however, resolves the `Stack`/`Repository` to act on using a completely different payload field, `repository.full_name`, in `Handler#stacks`. Because the signature check and the write-target lookup read two independently attacker-controlled fields of the same forged JSON body, a caller who knows (or is issued) the `webhook_secret` for *one* configured GitHub organization can forge a payload whose signature validates against that organization while `repository.full_name` points at a stack belonging to a completely different organization/repository, causing Shipit to act (sync commits, trigger deploys/merges via `stack.sync_github`, etc.) on that unrelated stack.

### Finding Description
`verify_signature` computes the org used for verification purely from the payload body: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up per-organization `webhook_secret`/app config from `secrets.github`, as documented for multi-org installs (`docs/setup.md`, "Using Multiple Github Applications"). [3](#0-2) 

Once the signature passes, `WebhooksController#create` dispatches the *raw parsed body* to handlers, unmodified: [4](#0-3) 

Every handler resolves its target `Stack`s from a **different** field of the same body — `repository.full_name` — with no cross-check against `repository.owner.login`/`organization.login` used for signature selection: [5](#0-4) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

For example, `PushHandler#process` uses that `stacks` scope to call `stack.sync_github(expected_head_sha: ...)`, driving Shipit's view of the repository's commit history and deployability: [6](#0-5) 

Because the HMAC only proves "the request body wasn't tampered with, and its `repository.owner.login`/`organization.login` field maps to an organization whose secret the sender knows," and never proves that the *acted-upon* `repository.full_name` belongs to that same organization, an attacker holding the `webhook_secret` of Organization A can produce a validly-signed payload where:
* `repository.owner.login` = `"OrgA"` (so `Shipit.github(organization: "OrgA")` is selected and the signature computed with OrgA's secret validates), while
* `repository.full_name` = `"OrgB/target-repo"` (an unrelated stack configured under a different, more sensitive organization on the same Shipit install).

This equality the code is supposed to preserve — *"organization that authenticated" == "repository that is written"* — is broken; the two are read from independent, unauthenticated-relative-to-each-other JSON fields.

### Impact Explanation
This lets an attacker who compromises or is issued a `webhook_secret` for a single low-trust GitHub organization/app configured on a shared Shipit instance forge webhooks that are processed as if legitimately sent for a stack belonging to a different, unrelated organization/repository. Depending on handler, this can inject fabricated commits/SHAs into another repository's stack (`PushHandler` → `sync_github`), alter pull request/merge-queue state (`pull_request/*` handlers, all keyed off the same `repository.full_name` pattern), or otherwise manipulate deploy/merge state for a repository the attacker has no legitimate access to — i.e., cross-repository/cross-organization writes, matching the Critical impact bar ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability requires the deployment to use the documented multi-organization GitHub App configuration (`config/secrets.yml`'s `github: { orgA: {...}, orgB: {...} }` schema) and requires the attacker to know at least one configured org's `webhook_secret` — which is a normal, first-class, in-scope configuration path (explicitly documented in `docs/setup.md`) rather than a misconfiguration, so it is within the engine's own trust model. Any tenant/org onboarded onto a shared multi-org Shipit instance is, by design, supposed to be limited to their own repositories; this bug removes that isolation.

### Recommendation
After selecting the GitHub App/secret via `repository_owner` and verifying the signature, re-derive the repository owner from `repository.full_name` (or `organization.login`, when used for org-level events) and assert it matches the same organization whose secret validated the signature before dispatching to handlers. Alternatively, bind `Handler#repository_name`/`#stacks` lookups to the organization already authenticated in `verify_signature`, rather than trusting the unrelated `full_name` field independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled webhook secret, e.g. leaked or intentionally `nil` per the shipped example config) and `OrgB` (victim org, has a real stack `OrgB/victim-repo`).
2. Craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(webhook_secret_of_OrgA, body)`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully using OrgA's secret.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` on the victim's stack — despite the request never being authenticated by OrgB's secret.

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
