# Gherkin Test Guidelines

When writing or modifying Gherkin `.feature` files, follow these rules to keep tests explicit and maintainable.

## Core principle

A scenario must be fully self-contained. A new team member should be able to read a single scenario and know exactly: what state the system is in, what action is taken, and what outcome to expect — without reading any other file.

## Rules

### Given: make all preconditions visible

Every piece of state a scenario depends on must appear as a `Given` step. Never rely on hidden setup in hooks or step definition side effects.

```gherkin
# Bad
Given I am on the dashboard

# Good
Given I am logged in as an admin user
And I am on the dashboard
```

### Background: use sparingly

Only use `Background` for setup that every scenario in the file requires. If one scenario doesn't need it, move it to an explicit `Given` instead.

### Actors and data: be concrete

Avoid "a user" or "the product". Use named actors and concrete data to eliminate ambiguity.

```gherkin
# Bad
Given a user exists

# Good
Given a customer "Carol" exists with an expired subscription
```

### Scenarios: keep them self-contained

- Each scenario resets to a clean state — never share state across scenarios
- Never let one scenario produce state consumed by a later one
- Reset shared state in `Before` hooks, not `After`

### Configuration: make it explicit

Feature flags, environment settings, and rate limits are state. Declare them as `Given` steps.

```gherkin
Given the "bulk-import" feature flag is enabled
And the rate limit is set to 100 requests per minute
```

### When: one action per scenario

One `When` step per scenario. Multiple `When` steps usually mean setup is disguised as action, or the scenario should be split.

### Then: assert business outcomes, not implementation

```gherkin
# Bad
Then the "submit-btn" element has class "disabled"

# Good
Then Carol should not be able to submit the form
```

### Step definitions: keep them thin

Step definitions must do exactly what the step text says — nothing more. No side effects beyond what is named, no mutable shared references like `this.lastCreatedUser`.

### Scenario titles: make them a contract

The title alone should communicate what is being tested without needing to read the steps.

```gherkin
# Bad
Scenario: Invalid input

# Good
Scenario: Submitting a renewal form with an expired credit card shows a payment error
```

## Review checklist

Before committing a `.feature` file, verify:

- [ ] Every precondition is in a `Given` step
- [ ] No scenario relies on state from another scenario
- [ ] All actors are named, all data is concrete
- [ ] Feature flags and config are declared explicitly
- [ ] Each scenario has exactly one `When`
- [ ] `Then` steps assert observable outcomes, not UI or internal state
- [ ] The scenario title is self-describing
