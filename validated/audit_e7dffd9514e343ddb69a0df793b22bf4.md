### Title
Multi-tenant GitHub App configurations let a webhook signed by one organization's `webhook_secret` write to a different organization's repository state - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When Shipit is configured with multiple GitHub App/organization entries (`secrets.github.<org>.webhook_secret`), the `WebhooksController` selects which organization's HMAC secret to verify a webhook against using `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body, while every event handler subsequently acts on a completely different field of that same unverified body — `repository.full_name` — to look up the `Stack`/`Repository` to mutate. Because these two fields are never cross-checked against each other, an attacker who legitimately controls one configured GitHub organization (and therefore legitimately knows/controls that organization's `webhook_secret`) can forge a payload whose signature is valid for their own org but whose `repository.full_name` points at a stack owned by a different, victim organization.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret exclusively from the owner named in the payload: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` resolves to a distinct `GitHubApp` instance per configured organization, each with its own independent `webhook_secret`, as seen in the multi-org secrets layout [3](#0-2)  and in `lib/shipit.rb#github`/`#github_app_config` [4](#0-3) .

Once the signature check passes, `WebhooksController#create` dispatches to handlers using only the `event` header — it does not re-validate that the org used for signing matches the repository the handler will touch: [5](#0-4) .

Every base handler, however, resolves the target `Repository`/`Stack` from a *different* JSON field, `repository.full_name`, which is never compared against `repository.owner.login`: [6](#0-5) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` uses this to trigger `stack.sync_github` on whatever stack matches `full_name` [7](#0-6) , and the pull-request handlers (`opened`, `closed`, `reopened`, `labeled`, `unlabeled`) similarly resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and then archive/unarchive/create review stacks accordingly, e.g. [8](#0-7) , [9](#0-8) .

**The equality binding this breaks:** "organisation whose credential authenticated the request" **≠** "repository the handler actually writes to." The engine implicitly assumes `repository.owner.login == repository.full_name`'s owner, but nothing enforces it. `repository_owner` (used to *select the trust root*) and `repository_name`/`full_name` (used to *select the write target*) are independent, attacker-controlled fields of the same unauthenticated JSON body.

### Impact Explanation
An attacker who is a legitimate admin of one GitHub org/repo onboarded into this Shipit instance (and thus knows that org's own `webhook_secret`, which they configured or can read from their own GitHub App settings) can sign an HMAC over a forged payload where `repository.owner.login` = their own org (so the signature check passes) but `repository.full_name` = `victim-org/victim-repo`. This lets them:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha:)` against a victim's stack, influencing which commits Shipit considers deployable.
- Trigger pull-request handlers to archive/unarchive/create review stacks (`ReviewStack#archive!`, `#unarchive!`) for a victim repository, causing unauthorized provisioning/deprovisioning actions and calling `Shipit::User.find_or_create_by_login!(params.sender["login"])` with an attacker-chosen login to attribute the action to an arbitrary user.
- Inject fabricated commit statuses / CI results for a victim's commits via the `status`/`check_suite` handlers (also keyed off `repository.full_name` independent of the authenticating org), potentially unblocking merge queue or deploy gating checks that depend on those statuses.

This is a cross-organization write achieved purely by a mismatch of trust binding — it satisfies the "cross-repository writes" / "unauthorized deploy or merge" criteria for the accepted Critical/High impact classes, since a party who never had any relationship to the victim org's repository is able to influence merge/deploy-adjacent state for that repository.

### Likelihood Explanation
Requires the attacker to be an authenticated/legitimate operator of at least one other organization already configured in the same multi-tenant Shipit deployment (i.e., they know or control that org's `webhook_secret`, which is standard for anyone administrating a GitHub App webhook for their own org). No GitHub credentials of the victim, no Shipit session, and no API token are required — only knowledge of one's own org's webhook secret and the ability to send an arbitrary HTTP POST to the shared `/github/webhooks` endpoint. This is realistic in any Shipit-engine deployment onboarding more than one organization (as documented and tested via `secrets_double_github_app.yml`), which is an explicitly supported configuration.

### Recommendation
Bind the signature-verifying organization to the repository being acted upon:
- After signature verification succeeds, re-derive the organization strictly from `repository.full_name`'s owner segment (not `repository.owner.login`) and assert it matches the organization/App whose secret validated the signature (or, simpler, require that `repository.owner.login` and the owner segment of `repository.full_name` are identical before verification is even attempted).
- Alternatively, look up the `Repository`/`Stack` model that owns `full_name`, determine the organization that owns it in Shipit's own configuration, and use that organization's `webhook_secret` exclusively for signature verification — never let the payload itself choose which secret validates it independent of the entity it claims to mutate.

### Proof of Concept
Configuration: Shipit multi-org secrets with `github.attacker-org.webhook_secret = S` and `github.victim-org.webhook_secret = <different/unknown to attacker>`, both onboarded (per `secrets_double_github_app.yml` pattern).

1. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` using their own known secret `S` for `attacker-org`.
3. POST to `/github/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`) and the signature verifies successfully against `S`.
5. `PushHandler#process` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — a mutation on a repository the attacker never authenticated for.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
