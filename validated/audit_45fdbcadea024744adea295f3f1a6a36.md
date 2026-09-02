This is exactly the trust-binding break the rules describe: "an organization that authenticated versus the repository that is written."

### Title
Webhook signature is verified against the organization derived from the unverified payload, but downstream handlers act on a separately-trusted `repository.full_name` field, letting a valid signature for one organization drive writes to any repository/stack name embedded in the payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's webhook secret to check the HMAC against using `repository_owner`, which is read straight from the *unverified* JSON body (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`). [1](#0-0) [2](#0-1)  Once the signature check for that organization passes, the raw, still-unverified body is handed to every registered handler for the event and re-parsed independently. [3](#0-2)  Handlers such as `PushHandler` resolve the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')`, a field distinct from the one used during signature verification (`repository.owner.login`). [4](#0-3) [5](#0-4) 

### Finding Description
Shipit supports multiple GitHub Apps/organizations, each with an independent `webhook_secret` configured under `config/secrets.yml`'s `github.<org>` keys. [6](#0-5)  The equality the deployment trust model needs to hold is:

`organization whose webhook_secret validated this HMAC == organization that owns the repository/stack the handler subsequently writes to`

`verify_signature` computes the "authenticating organization" from `repository_owner`, then does `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0)  Nothing ties this owner string to the `full_name` value that `Handler#stacks`/`#repository_name` later uses to find the `Repository`/`Stack` to mutate: [4](#0-3) 

Because the two fields (`repository.owner.login` and `repository.full_name`) are independent JSON keys in the same unverified body, a party who legitimately controls a webhook secret for *one* configured organization ("OrgA") can send a request where:
- `repository.owner.login = "OrgA"` (so `verify_signature` picks OrgA's secret, and the request is HMAC-signed with OrgA's real secret — passes),
- `repository.full_name = "OrgB/some-repo"` (used later by `PushHandler`, `OpenedHandler`, etc. to find and mutate OrgB's `Stack`/`Repository`/`ReviewStackAdapter` objects). [7](#0-6) 

This crosses the "organization authenticated vs repository written" boundary described in scope: the signature check authenticates possession of OrgA's secret, but the actual write (triggering a sync/deploy job, creating review stacks, closing PRs) targets whatever `full_name` the attacker embeds, regardless of which secret validated the request.

### Impact Explanation
An attacker who is a legitimate installer/maintainer of one GitHub organization configured in Shipit (and thus knows or can trigger deliveries signed with that org's `webhook_secret`) can forge webhook deliveries that are accepted as valid, then use the independent `full_name`/`repository` fields processed by handlers (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) to affect stacks belonging to a *different* organization/repository also hosted on the same Shipit instance. This is a cross-repository write: it can enqueue `GithubSyncJob` for another org's stack, or drive `ReviewStackAdapter.find_or_create!`/close/label logic against another organization's review stacks — an unauthorized action originating from a boundary meant to isolate organizations from each other.

### Likelihood Explanation
Requires the attacker to already have a legitimately configured webhook secret for at least one organization on the shared Shipit instance (i.e., control of a GitHub App installation covered by `config/secrets.yml`). This is a real but non-trivial precondition — it only matters in multi-organization Shipit deployments (`docs/setup.md`'s "Using Multiple Github Applications" documents this as a supported configuration [8](#0-7) ). Once that precondition is met, forging the payload requires only a normal HTTP POST with a self-computed HMAC — no additional secrets or session/token access needed for the cross-org write, which matches the "unprivileged attacker" framing relative to the target org.

### Recommendation
Bind the verified signature to the same fields the handlers act on: after verifying the signature for the organization derived from the payload, re-validate that every `repository.full_name`/`organization.login` referenced by the handler's parsed params belongs to that same authenticated organization before performing any state changes (e.g., compare the owner segment of `full_name` against `repository_owner` used in `verify_signature`, and reject mismatches with 422).

### Proof of Concept
1. Configure two orgs in `secrets.yml`: `OrgA` (webhook_secret `SA`) and `OrgB` (webhook_secret `SB`), each with a Shipit-tracked repository/stack, per the documented multi-org config. [8](#0-7) 
2. As someone with legitimate access to trigger/sign webhook deliveries for `OrgA` (e.g., an OrgA app installer), craft a `push` event JSON body with:
   - `"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}`
   - `"ref": "refs/heads/<tracked-branch>"`, `"after": "<attacker-chosen-sha>"`
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(SA, raw_body)>` using OrgA's known secret.
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and validates successfully since the signature matches OrgA's secret. [1](#0-0) 
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and enqueues a sync for OrgB's stack — a write against OrgB triggered by a signature that only proves knowledge of OrgA's secret. [4](#0-3) [5](#0-4)

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
