Feature: Authenticated and encrypted SNMP trap sending at authPriv security level

  Verify that the agent correctly authenticates and encrypts outbound SNMPv3
  traps using HMAC-SHA-256 and AES-128-CFB when configured with an authPriv
  USM user, and that a trap receiver configured with matching credentials can
  decrypt and verify the trap content.

  Background:
    Given snmptrapd is running

  @REQ-0105
  Scenario: Cold-start trap at authPriv includes mandatory RFC 3416 varbinds
    When the agent at authPriv with user "privtrapuser" and auth password "authpassword" sends a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "priv-cold-start"
    And trap "priv-cold-start" has varbind "1.3.6.1.2.1.1.3.0"
    And trap "priv-cold-start" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"

  @REQ-0105
  Scenario: Trap with Integer32 varbinds at authPriv preserves values in transit
    When the agent at authPriv with user "privtrapuser" and auth password "authpassword" sends a trap with OID "1.3.6.1.6.3.1.1.5.3" and varbinds:
      | oid                    | type      | value |
      | 1.3.6.1.2.1.2.2.1.1.1 | Integer32 | 1     |
      | 1.3.6.1.2.1.2.2.1.7.1 | Integer32 | 2     |
    Then snmptrapd receives a trap named "priv-link-down"
    And trap "priv-link-down" has varbind "1.3.6.1.2.1.2.2.1.1.1" with value "1"
    And trap "priv-link-down" has varbind "1.3.6.1.2.1.2.2.1.7.1" with value "2"

  @REQ-0105
  Scenario: Authenticated and encrypted trap at authPriv is delivered to multiple destinations
    Given a second snmptrapd named "priv-receiver-2" is running
    When the agent at authPriv with user "privtrapuser" and auth password "authpassword" sends to receivers "snmptrapd" and "priv-receiver-2" a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "priv-primary"
    And trap "priv-primary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
    And "priv-receiver-2" receives a trap named "priv-secondary"
    And trap "priv-secondary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
