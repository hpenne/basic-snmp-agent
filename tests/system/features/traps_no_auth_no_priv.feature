Feature: SNMPv3 trap sending at noAuthNoPriv security level

  Verify that the agent correctly sends SNMPv3 traps at noAuthNoPriv
  security level (USM user name but no authentication or encryption),
  and that a trap receiver configured with disableAuthorization can
  process the trap content.

  Background:
    Given snmptrapd is running

  @REQ-0106
  Scenario: Cold-start trap at noAuthNoPriv includes mandatory RFC 3416 varbinds
    When the agent at noAuthNoPriv with user "noauthuser" sends a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "noauth-cold-start"
    And trap "noauth-cold-start" has varbind "1.3.6.1.2.1.1.3.0"
    And trap "noauth-cold-start" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"

  @REQ-0106
  Scenario: Trap with Integer32 varbinds at noAuthNoPriv preserves values in transit
    When the agent at noAuthNoPriv with user "noauthuser" sends a trap with OID "1.3.6.1.6.3.1.1.5.3" and varbinds:
      | oid                    | type      | value |
      | 1.3.6.1.2.1.2.2.1.1.1 | Integer32 | 1     |
      | 1.3.6.1.2.1.2.2.1.7.1 | Integer32 | 2     |
    Then snmptrapd receives a trap named "noauth-link-down"
    And trap "noauth-link-down" has varbind "1.3.6.1.2.1.2.2.1.1.1" with value "1"
    And trap "noauth-link-down" has varbind "1.3.6.1.2.1.2.2.1.7.1" with value "2"

  @REQ-0106
  Scenario: Unauthenticated trap at noAuthNoPriv is delivered to multiple destinations
    Given a second snmptrapd named "noauth-receiver-2" is running
    When the agent at noAuthNoPriv with user "noauthuser" sends to receivers "snmptrapd" and "noauth-receiver-2" a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "noauth-primary"
    And trap "noauth-primary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
    And "noauth-receiver-2" receives a trap named "noauth-secondary"
    And trap "noauth-secondary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
