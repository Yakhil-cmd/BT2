### Title
Webhook organization-secret verification does not bind the payload's `repository.full_name`, allowing cross-organization commit-status / push forgery in a multi-tenant Shipit instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The reported bug class (a value acted upon by contract logic that is not covered by the invariant the code actually verifies) maps onto how `Shipit::WebhooksController` selects which GitHub App secret to verify a webhook's HMAC against, versus which repository/stack the resulting handler actually mutates.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from `repository.owner.login` (or `organization.login`) and uses that org's `webhook_secret` to validate `X-Hub-Signature`: [1](#0-0) [2](#0-1) 

Once the signature is accepted, every handler resolves the target `Stack`/`Repository` from a *different* field of the same JSON body — `repository.full_name` — with no check that its owner segment matches the `repository.owner.login` used to select the verifying secret: [3](#0-2) [4](#0-3) 

Shipit explicitly supports hosting multiple, mutually untrusted GitHub organizations behind one instance, each with its own `webhook_secret` under `secrets.github.<org>` [5](#0-4)  resolved via `Shipit.github_app_config` [6](#0-5) .

Because the code that picks the verifying secret (`repository.owner.login`) and the code that picks the mutated resource (`repository.full_name`) read two independent JSON keys, an attacker who legitimately controls one tenant organization ("OrgA", with a valid GitHub App installation and thus knowledge of OrgA's `webhook_secret`) can craft an arbitrary JSON body where:
- `repository.owner.login = "OrgA"` — satisfies `verify_signature`, since the attacker can produce a correct HMAC with OrgA's own secret over the whole body.
- `repository.full_name = "OrgB/victim-repo"` — an unrelated organization/repository also hosted on the same Shipit instance, which the attacker does not control.

Nothing in `verify_signature` or `Handler#repository_name`/`Repository.from_github_repo_name` cross-checks that the two fields agree, so the request is accepted and dispatched against OrgB's `Stack`.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written." Concretely, `StatusHandler` and `PushHandler` operate on whatever `Stack` `Repository.from_github_repo_name(payload.dig('repository','full_name'))` returns [3](#0-2) , so a tenant admin of OrgA can inject forged commit statuses or push events attributed to OrgB's repository/stack purely by knowing OrgA's secret. Forged `status` events can fabricate green CI checks on arbitrary commits of an unrelated organization's stack, which Shipit's deploy pipeline uses to gate whether a commit is deployable — enabling an unauthorized deploy decision on a stack the attacker has no legitimate access to. This is a cross-repository/cross-tenant write achieved without any credential belonging to the victim organization, satisfying the Critical bar ("cross-repository writes" / "unauthorized deploy").

### Likelihood Explanation
Exploitability requires the Shipit operator to run the documented multi-organization configuration (`config/secrets.yml` keyed by multiple GitHub orgs) and the attacker to be a legitimate administrator/installer of one of those tenant orgs — a low but realistic bar in any shared/multi-tenant Shipit deployment, since it needs no access to the victim org at all, only to their own.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handlers::Handler`), after signature verification, assert that the organization used to select the verifying secret matches the owner segment of `repository.full_name` (and of `organization.login` for org-scoped events) before dispatching to handlers, rejecting mismatches with `422`.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (as in `docs/setup.md`'s multi-app example).
2. As an attacker who administers `OrgA`'s installed GitHub App (and thus knows `OrgA`'s `webhook_secret`), build a `status` event JSON body:
   ```json
   {
     "sha": "<any sha in OrgB/victim-repo>",
     "state": "success",
     "context": "ci/tests",
     "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1 of body using OrgA's webhook_secret>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` as `"OrgA"` [2](#0-1) , fetches OrgA's app/secret, and the signature checks out.
5. `StatusHandler`/`Handler#repository_name` resolves the target repository from `repository.full_name = "OrgB/victim-repo"` [3](#0-2) , and the forged commit status is recorded against OrgB's stack — despite the attacker having no credentials or access to OrgB.

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

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
