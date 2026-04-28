Feature: SNMP MIB reads over plain TCP

  Verify that the agent correctly handles SNMPv3 GET, GETNEXT, and GETBULK
  requests from net-snmp CLI tools over a plain TCP connection.

  Background:
    Given a test-agent-mib instance is running with engine ID "0x80001f8804746573742d6167656e742d6d6962"

  @REQ-0021 @REQ-0022 @REQ-0023 @REQ-0050 @REQ-0051 @REQ-0052 @REQ-0055 @REQ-0060 @REQ-0062 @REQ-0063 @REQ-0066 @REQ-0068 @REQ-0069 @REQ-0070 @REQ-0071 @REQ-0072 @REQ-0073 @REQ-0075 @REQ-0103
  Scenario: GET returns the value for a present OID
    When snmpget queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"

  @REQ-0021 @REQ-0022 @REQ-0023 @REQ-0068 @REQ-0073
  Scenario: GET returns noSuchObject for an absent OID
    When snmpget queries OID "1.3.6.1.2.1.99.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.99.1.0" with exception "No Such Object"

  @REQ-0021 @REQ-0022 @REQ-0024 @REQ-0061 @REQ-0066 @REQ-0068 @REQ-0073
  Scenario: GETNEXT returns the lexicographically next OID
    When snmpgetnext queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0"

  @REQ-0021 @REQ-0022 @REQ-0024 @REQ-0025 @REQ-0068 @REQ-0073
  Scenario: GETNEXT at end of MIB returns endOfMibView
    When snmpgetnext queries OID "1.3.6.1.2.1.1.5.0" from the agent
    Then the SNMP response contains exception "No more variables left in this MIB View"

  @REQ-0021 @REQ-0022 @REQ-0026 @REQ-0027 @REQ-0061 @REQ-0066 @REQ-0068 @REQ-0073
  Scenario: GETBULK with max-repetitions=0 returns only non-repeater varbinds
    When snmpbulkget with non-repeaters=1 and max-repetitions=0 queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0"
    And the SNMP response does not contain OID "1.3.6.1.2.1.1.5.0"

  @REQ-0021 @REQ-0022 @REQ-0026 @REQ-0029 @REQ-0030 @REQ-0031 @REQ-0068 @REQ-0073
  Scenario: GETBULK returns multiple values with max-repetitions=2
    When snmpbulkget with non-repeaters=0 and max-repetitions=2 queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0"
    And the SNMP response contains OID "1.3.6.1.2.1.1.5.0"

  @REQ-0032 @REQ-0068 @REQ-0073
  Scenario: SET request returns notWritable error
    When snmpset queries OID "1.3.6.1.2.1.1.5.0" with string value "changed" from the agent
    Then the SNMP response contains error "notWritable"

  @REQ-0104
  Scenario: Request with wrong contextEngineID receives Report PDU
    When snmpget with wrong context engine ID "0x80001f8804776f726f6e67" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response is a Report PDU

  @REQ-0056 @REQ-0058
  Scenario: Request with non-empty context name is silently discarded
    When snmpget with context name "badcontext" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0093
  Scenario: GET without explicit engine ID succeeds after automatic engine-ID discovery
    When snmpget without explicit engine ID queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"
