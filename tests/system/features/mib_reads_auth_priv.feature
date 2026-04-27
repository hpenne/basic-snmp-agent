Feature: SNMP MIB reads with authPriv security over plain TCP

  Verify that the agent correctly handles SNMPv3 requests from net-snmp CLI tools
  when authenticated with HMAC-SHA-256 and encrypted with AES-128-CFB (authPriv
  security level), and that it correctly rejects requests with wrong credentials
  or insufficient security level.

  Background:
    Given a test-agent-mib-auth-priv instance is running with engine ID "0x80001f8804746573742d6167656e742d70726976"

  @REQ-0078 @REQ-0079 @REQ-0101 @REQ-0107
  Scenario: GET with correct authPriv credentials succeeds
    When snmpget at authPriv with user "privuser", auth password "authpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"

  @REQ-0078 @REQ-0079 @REQ-0101 @REQ-0107
  Scenario: GETNEXT with correct authPriv credentials succeeds
    When snmpgetnext at authPriv with user "privuser", auth password "authpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0" with string value "Timeticks: (0) 0:00:00.00"

  @REQ-0078 @REQ-0079 @REQ-0101 @REQ-0107
  Scenario: GETBULK with correct authPriv credentials succeeds
    When snmpbulkget at authPriv with user "privuser", auth password "authpassword", and priv password "privpassword", non-repeaters=0 and max-repetitions=2 queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0" with string value "Timeticks: (0) 0:00:00.00"
    And the SNMP response contains OID "1.3.6.1.2.1.1.5.0" with string value "test-agent-mib-auth-priv"

  @REQ-0080 @REQ-0093 @REQ-0101 @REQ-0107
  Scenario: GET without explicit engine ID succeeds after automatic discovery with authPriv
    When snmpget at authPriv without explicit engine ID with user "privuser", auth password "authpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"

  @REQ-0100
  Scenario: GET with wrong authentication password is rejected
    When snmpget at authPriv with user "privuser", auth password "wrongpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0101
  Scenario: GET with wrong privacy password is rejected
    When snmpget at authPriv with user "privuser", auth password "authpassword", and priv password "wrongprivpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0078
  Scenario: GET with unknown user name is rejected
    When snmpget at authPriv with user "nobody", auth password "authpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0079
  Scenario: GET at noAuthNoPriv security level is rejected by authPriv agent
    When snmpget at noAuthNoPriv with user "privuser" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0079
  Scenario: GET at authNoPriv security level is rejected by authPriv agent
    When snmpget at authNoPriv with user "privuser" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0104
  Scenario: GET with correct authPriv credentials but wrong contextEngineID receives Report PDU
    When snmpget at authPriv with wrong context engine ID "0x80001f8804776f726f6e67" with user "privuser", auth password "authpassword", and priv password "privpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response is a Report PDU
