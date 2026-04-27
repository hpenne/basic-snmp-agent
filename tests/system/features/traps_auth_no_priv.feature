Feature: Authenticated SNMP trap sending at authNoPriv security level

  Verify that the agent correctly authenticates outbound SNMPv3 traps using
  HMAC-SHA-256 when configured with an authNoPriv USM user, and that a trap
  receiver configured with matching credentials can verify the HMAC and
  process the trap content.

  Background:
    Given snmptrapd is running

  @REQ-0105
  Scenario: Cold-start trap at authNoPriv includes mandatory RFC 3416 varbinds
    When the agent at authNoPriv with user "authuser" and password "authpassword" sends a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "auth-cold-start"
    And trap "auth-cold-start" has varbind "1.3.6.1.2.1.1.3.0"
    And trap "auth-cold-start" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"

  @REQ-0105
  Scenario: Trap with Integer32 varbinds at authNoPriv preserves values in transit
    When the agent at authNoPriv with user "authuser" and password "authpassword" sends a trap with OID "1.3.6.1.6.3.1.1.5.3" and varbinds:
      | oid                    | type      | value |
      | 1.3.6.1.2.1.2.2.1.1.1 | Integer32 | 1     |
      | 1.3.6.1.2.1.2.2.1.7.1 | Integer32 | 2     |
    Then snmptrapd receives a trap named "auth-link-down"
    And trap "auth-link-down" has varbind "1.3.6.1.2.1.2.2.1.1.1" with value "1"
    And trap "auth-link-down" has varbind "1.3.6.1.2.1.2.2.1.7.1" with value "2"

  @REQ-0105
  Scenario: Authenticated trap at authNoPriv is delivered to multiple destinations
    Given a second snmptrapd named "auth-receiver-2" is running
    When the agent at authNoPriv with user "authuser" and password "authpassword" sends to receivers "snmptrapd" and "auth-receiver-2" a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "auth-primary"
    And trap "auth-primary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
    And "auth-receiver-2" receives a trap named "auth-secondary"
    And trap "auth-secondary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
