### Title
Webhook organization used for signature verification is never bound to the repository the payload actually targets, allowing cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate an inbound webhook against using `repository.owner.login` from the JSON payload, but every downstream event handler resolves the target `Repository`/`Stack` using a *different* payload field, `repository.full_name`. Because these two fields are never cross-checked, an attacker who legitimately controls any GitHub organization that has the Shipit GitHub App installed (and therefore legitimately knows that organization's own `webhook_secret`) can hand-craft a webhook body whose `repository.owner.login` names their own org (so the HMAC check passes) while `repository.full_name` names an unrelated victim repository configured in the same Shipit instance. This drives Shipit's webhook handlers (push sync, review-stack provisioning, etc.) against the victim's stack.

### Finding Description
`verify_signature` in [1](#0-0)  picks the `GitHubApp` (and thus the secret used for HMAC verification) purely from `repository_owner`, defined as: [2](#0-1) 

Every webhook handler, however, resolves which `Repository`/`Stack` to act on from a completely separate field, `repository.full_name`: [3](#0-2) 

`Repository.from_github_repo_name` simply splits that string into owner/name and looks the record up, with no relationship at all to which organization's secret verified the request: [4](#0-3) 

This is used, for example, in `PushHandler`, which syncs the resolved stacks with attacker-chosen commit data: [5](#0-4) 

and in `OpenedHandler`, which creates and enqueues a brand-new `ReviewStack` for provisioning using attacker-supplied PR fields: [6](#0-5) [7](#0-6) 

The binding that is broken is: *organization that authenticated the request* (`repository.owner.login`, used to pick the webhook secret) **≠** *repository the payload's handlers act on* (`repository.full_name`, used for the actual DB lookup). The signature only proves the payload was signed by the organization named in `repository.owner.login`; it says nothing about the truthfulness of `repository.full_name`, yet the latter alone determines which Shipit `Repository`/`Stack` is mutated.

### Impact Explanation
An attacker who administers any GitHub organization onboarded to this Shipit instance (a routine, unprivileged action — no Shipit session, `ApiClient` token, or `webhook_secret` of the *victim* org is required) can forge a signed webhook whose `repository.owner.login` matches their own org (passing signature verification with their own legitimately-known secret) but whose `repository.full_name` names an arbitrary victim repository hosted on the same Shipit instance. This lets them:
- force `PushHandler` to invoke `stack.sync_github` on the victim stack with an attacker-chosen `expected_head_sha`, which can trigger the victim's continuous-deployment pipeline, and
- force `OpenedHandler`/`ReviewStackAdapter#create!` to create and queue-for-provisioning a brand-new `ReviewStack` on the victim's repository, using attacker-controlled `pull_request.head.ref`/PR number, causing Shipit to check out and deploy that ref using the victim repository's own GitHub App credentials.

This results in an unauthorized deploy/provisioning action being triggered against a repository the attacker does not own or have write access to, satisfying the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Exploitation only requires the attacker to control any GitHub organization already onboarded to the shared Shipit deployment (a common multi-tenant configuration per `docs/setup.md`'s "Using Multiple Github Applications" section) and to POST a hand-signed HTTP request directly to the public `/webhooks` endpoint — no Shipit account, session, or victim secret is needed. This is a realistic scenario for any Shipit installation serving more than one GitHub organization.

### Recommendation
Bind the two identities together before dispatching to handlers: after `verify_signature` succeeds, assert that `repository.full_name`'s owner segment equals the `repository_owner`/`organization` value that was actually used to select the signing secret (and reject the request otherwise). Equivalently, `Handler#repository_name`/`Repository.from_github_repo_name` lookups should be constrained to repositories whose stored `owner` matches the organization that authenticated the webhook, not merely whatever `full_name` the payload claims.

### Proof of Concept
1. Attacker controls GitHub org `attacker-org`, which has the Shipit GitHub App installed (thus attacker legitimately knows `attacker-org`'s `webhook_secret`).
2. Attacker crafts a `pull_request` "opened" JSON payload with:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `pull_request.head.ref = "main"`, `pull_request.head.sha = <a real commit sha in victim-repo>`, `number = 9999`
3. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: pull_request`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the signature validates successfully.
6. `OpenedHandler` resolves `repository` via `Repository.from_github_repo_name("victim-org/victim-repo")`, finds the real victim `Repository`, and — if `review_stacks_enabled`/`provisioning_behavior_allow_all?` is set — creates and queues a new `ReviewStack` for provisioning against the victim's actual repository, entirely under attacker control of the payload contents.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
