This confirms Shipit supports multi-organization GitHub App configuration: `Shipit.github(organization:)` looks up a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key in `secrets.github` [1](#0-0) . This is exactly the structural precondition needed for the analog.

### Title
Webhook signature is verified against the payload's claimed organization while event handlers act on an unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the unauthenticated JSON body (`repository.owner.login`, or `organization.login` as a fallback). Once the signature check for *that* organization passes, the entire raw payload is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and every handler resolves the actual repository/stack to mutate using a *different* field of the same payload — `repository.full_name` — with no re-check that it belongs to the organization whose secret validated the request.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `GitHubApp` instance (and therefore a per-organization `webhook_secret`) via `github_app_config(organization)` when the installation uses the multi-org schema [1](#0-0) .

After signature verification succeeds, every handler (e.g. `PushHandler`) resolves the target using `Handler#repository_name`/`#stacks`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) [4](#0-3) 

Other handlers (pull request opened/labeled/unlabeled/edited/reopened) equally derive the acted-upon `Repository`/`Stack` from `params.repository.full_name` [5](#0-4) [6](#0-5) .

The binding that should hold is:
```
organization used to select webhook_secret for HMAC verification == organization that owns the repository.full_name being written to
```
Nothing in `verify_signature` or in `Handler` enforces this. `repository.owner.login` (used for verification) and `repository.full_name` (used for the write) are two independently attacker-supplied fields of the same unsigned-until-verified JSON body; the signature only proves the raw bytes were produced by whoever holds the secret for the organization named in `repository.owner.login` — it does not constrain what `repository.full_name` says.

### Impact Explanation
If an attacker legitimately controls a GitHub App installation on their own low-privilege organization/repo (a scenario Shipit explicitly supports via multi-org `secrets.github` configuration), they possess that organization's genuine `webhook_secret`. They can self-sign an arbitrary payload with `repository.owner.login` set to their own org (so `verify_signature` succeeds) while setting `repository.full_name` to any other repository hosted by the same Shipit instance under a different, victim organization. Handlers will then act on the victim repository/stack — e.g. `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for the victim's stack, and PR-label/open/reopen handlers can archive/unarchive/create review stacks or mutate `PullRequest` records cross-repository. This is a cross-repository write triggered by forging the deployment-trust binding between "organization that authenticated the signature" and "repository that is written," matching the report's bug class (an authenticated context used to fetch a boundary that is not re-validated against the field actually acted upon).

### Likelihood Explanation
Requires the target Shipit deployment to be configured for multiple organizations (the documented multi-org `secrets.github` schema) and requires the attacker to control (or have webhook access to) at least one org/repo hosted on that instance — no `ApiClient` token, GitHub App private key, or session is needed, satisfying the "unprivileged attacker" constraint. Single-organization deployments (the common case, where `Shipit.github(organization:)` ignores the argument via `github_default_organization` returning nil) are not affected since there is only one secret to verify against regardless of the claimed owner.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (the field actually used to resolve the `Repository`/`Stack`) and require it to match the organization whose secret validated the signature, rejecting the payload otherwise. Alternatively, always verify against the organization owning `repository.full_name` rather than the attacker-controlled `repository.owner.login`/`organization.login` fallback used today.

### Proof of Concept
1. Deploy Shipit with multi-org config: orgs `attacker-org` and `victim-org`, each with a distinct `webhook_secret`, both having repos onboarded as Shipit stacks.
2. Attacker (owner of a repo under `attacker-org`, with legitimate webhook access to that org's GitHub App and therefore its `webhook_secret`) crafts a push payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw JSON body and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, validates successfully since the attacker used the correct secret for that org [7](#0-6) .
5. `PushHandler#process` runs `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack [3](#0-2) [4](#0-3) , forcing a sync/deploy-trigger cycle against `victim-org/victim-repo` despite the request never being authenticated against that organization.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
