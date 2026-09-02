### Title
CCMenu API bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` can only ever resolve stacks from its own `stack_id` via the `stacks`/`stack` helper methods. `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, completely bypassing this scoping. Any valid `ApiClient` token — even one that is supposed to be restricted to a single stack — can therefore query the CI/deploy status of every other stack in the installation through the CCMenu endpoint.

### Finding Description
`ApiClient` supports an optional `stack` association used to restrict a token to a single stack: [1](#0-0) 

`BaseController` implements the enforcement of this binding: any controller resolving "the stack" for the current request is supposed to go through `stacks`, which filters by `current_api_client.stack_id` when the client is scoped: [2](#0-1) 

`CCMenuController` inherits from `BaseController` (so it inherits `require_permission :read, :stack`, which only checks the client has the `read:stack` permission string, not which stack), but it locally overrides `stack` to bypass the scoped `stacks` collection entirely: [3](#0-2) 

`ApiClient#check_permissions!` only validates the permission name (`read:stack`), it has no awareness of `stack_id`: [4](#0-3) 

The `here_come_the_walrus` test fixture demonstrates that stack-scoped `ApiClient`s are a real, supported configuration in this codebase, and the existing test suite explicitly validates that such a token is confined to its stack in the sibling `StacksController`: [5](#0-4) [6](#0-5) 

The trust binding broken here is: `ApiClient.stack_id (the stack a token authorizes)` == `params[:stack_id] resolved in CCMenuController#stack (the stack actually touched)`. Before any PR/change, `BaseController#stack` correctly enforces this equality for every other API resource (`StacksController`, `HooksController`, etc., which all rely on `stacks`/`stack` from `BaseController`). `CCMenuController` is the one path where the equality is not enforced — the code accepts any `stack_id` param regardless of the token's `stack_id` value.

### Impact Explanation
An attacker who holds (or is given) a stack-scoped `ApiClient` token — for example a "CCMenu Client" token generated for one stack via `CCMenuUrlController`, or any manually scoped client — can request `/api/stacks/:any_other_stack_id/ccmenu.xml` and receive that other stack's build/deploy status (`lastBuildStatus`, `activity`, `lastBuildLabel`, `webUrl`, lock state) rather than being confined to the one stack it was authorized for: [7](#0-6) 

This is an authorization-scope escalation: a token explicitly restricted to a stack can read state belonging to arbitrary other stacks in the installation, which the engine's own scoping design (`BaseController#stacks`) is meant to prevent.

### Likelihood Explanation
Any actor possessing a valid, but stack-limited, `ApiClient` token can exploit this trivially with a single unauthenticated-scope-check GET request; no privilege escalation beyond having any read-scoped token is required, and the endpoint is unauthenticated aside from the token itself (`authenticate_api_client` in `CCMenuController` even allows passing the token as a query-string parameter, lowering the bar further): [8](#0-7) 

### Recommendation
Change `CCMenuController#stack` to resolve the stack through the scoped `stacks` collection (i.e. `stacks.from_param!(params[:stack_id])`) exactly as `BaseController#stack` does, so a stack-scoped `ApiClient` cannot query stacks outside its authorized `stack_id`.

### Proof of Concept
1. Obtain (or have an admin generate) an `ApiClient` scoped to `stack_id = A` with `permissions: ['read:stack']` (e.g., via the CCMenu "Fetch URL" button on stack A's settings page, which creates such a token through `CCMenuUrlController#client`).
2. Using that token's `authentication_token`, issue: `GET /api/stacks/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu.xml?token=<tokenA>` where stack B is a different stack than A.
3. Observe the request succeeds and returns stack B's `lastBuildStatus`, `activity`, and other build metadata, even though the token was only meant to authorize access to stack A — because `CCMenuController#stack` calls `Stack.from_param!` unscoped instead of the token-scoped `stacks.from_param!` used everywhere else in the API.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
end
```
