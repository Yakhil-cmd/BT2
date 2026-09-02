### Title
Webhook signature is verified against `repository.owner.login`, but Stacks are resolved from the independently-controlled `repository.full_name` field, enabling cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
This is a structural analog of the `TypedMemView.sameType` bug: two different sub-fields of the same signed blob are used for two different purposes, and only one of them is actually bound to the trust decision. In `TypedMemView` the flag byte was outside the region actually compared; here, the field used to *select which secret authenticates the request* (`repository.owner.login` / `organization.login`) is disjoint from the field used to *select which Stack/Repository record is mutated* (`repository.full_name`). Both live in the same JSON body, but nothing forces them to agree.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp`/secret to validate the HMAC using `repository_owner`: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a **distinct config (and distinct `webhook_secret`) per organization** when Shipit is configured for multiple GitHub organizations: [3](#0-2) 

Once the signature check passes (i.e., the body's HMAC matches organization A's `webhook_secret`), every handler resolves the actual target **Stack/Repository** from a completely different field of the same body — `repository.full_name` — with no re-check that it belongs to the organization whose secret was used to authenticate the request: [4](#0-3) [5](#0-4) 

The same pattern repeats in every PR-related handler (`ClosedHandler`, `OpenedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `LabelCapturingHandler`), all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [6](#0-5) [7](#0-6) 

Because `Repository.from_github_repo_name` parses owner/name straight out of `full_name` independently of `repository_owner`: [5](#0-4) 

the "organization that authenticated" (via its `webhook_secret`) and the "repository that is written" (via `full_name`) are never checked for equality anywhere in this flow.

### Impact Explanation
In a multi-org Shipit deployment (`Shipit.github_organizations`), each org has its own GitHub App installation and its own `webhook_secret`. Anyone with the ability to install/configure a GitHub App webhook for *any one* of those organizations (e.g., an org admin of a low-trust tenant org onboarded to the same Shipit instance) knows that org's `webhook_secret` — this is normal, unprivileged setup, not a Shipit credential. That party can POST directly to `/github/webhooks` with:
- `repository.owner.login` = their own org (so `verify_signature`/`verify_webhook_signature` succeeds using their own known secret), and
- `repository.full_name` = `"victim-org/victim-repo"` (any other org's repo registered as a Shipit `Repository`).

The handlers then act on the victim's `Stack`/`ReviewStack` — e.g. `PushHandler#process` enqueues `stack.sync_github(expected_head_sha:)` and `ReopenedHandler`/`UnlabeledHandler` call `stack.unarchive!`/`stack.archive!` — for a Stack that has nothing to do with the organization whose secret authenticated the request. This is a cross-repository/cross-tenant write triggered without any privilege over the victim organization, matching the "Critical: cross-repository writes / unauthorized deploy or rollback" bar.

### Likelihood Explanation
This only manifests when a single Shipit instance is configured with multiple GitHub organizations (the `github:` multi-org schema in `lib/shipit.rb#github_app_config`), which is an explicitly supported configuration mode. Any party legitimately allowed to configure a webhook for one tenant org (i.e., a completely unprivileged actor with respect to any *other* tenant) can carry out the attack with a single crafted HTTP request; no Shipit session, API token, or GitHub write access to the victim repo is required.

### Recommendation
After signature verification, re-derive `repository_owner` from the *same* field used for the write path (`repository.full_name`'s owner segment) and require it to match the organization whose secret validated the signature, or verify the signature using the `webhook_secret` scoped to `repository.full_name`'s owner rather than a separately-dug `repository.owner.login`/`organization.login`. At minimum, `Handler#repository_name`/`Repository.from_github_repo_name` should assert that the resolved repository's `owner` equals the `repository_owner` that authenticated the request before any mutation is performed.

### Proof of Concept
1. Shipit is configured with two orgs, `attacker-org` and `victim-org`, each with its own GitHub App/`webhook_secret` (multi-org schema in `secrets.github`).
2. Attacker knows `attacker-org`'s `webhook_secret` (they legitimately administer that org's GitHub App).
3. Attacker sends:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC(attacker-org secret, body)>

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC matches → `verified = true`.
5. `PushHandler#process` calls `stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")` → finds the victim's real `Repository`/`Stack` and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, an action never authorized by `victim-org`.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
