package conversion

import "strings"

// TODO: scope license file search to LICENSE files and use templates for tags to convert individual rules into one rule
const license_rules = `
- ruleID: apache-license-1
  description: "Apache 1.0 license file"
  when:
    builtin.filecontent:
      pattern: "Apache License 1.0"
  tag: ["Apache License 1.0"]
- ruleID: apache-license-11
  description: "Apache 1.1 license file"
  when:
    builtin.filecontent:
      pattern: "Apache License 1.1"
  tag: ["Apache License 1.1"]
- ruleID: apache-license-2
  description: "Apache 2.0 license file"
  when:
    builtin.filecontent:
      pattern: "Apache License 2.0"
  tag: ["Apache License 2.0"]
- ruleID: mozilla-public-2-license
  description: "Mozilla Public 2.0 license file"
  when:
    builtin.filecontent:
      pattern: "Mozilla Public License 2.0"
  tag: ["Mozilla Public License 2.0"]
- ruleID: gnu-gpl-license
  description: "GNU GPL license file"
  when:
    builtin.filecontent:
      pattern: "GNU GPL"
  tag: ["GNU GPL"]
- ruleID: gnu-lgpl-license
  description: "GNU LGPL license file"
  when:
    builtin.filecontent:
      pattern: "GNU LGPL"
  tag: ["GNU LGPL"]
- ruleID: cddl-license
  description: "CDDL license file"
  when:
    builtin.filecontent:
      pattern: "CDDL"
  tag: ["CDDL"]
- ruleID: eclipse-public-license
  description: "Eclipse public license file"
  when:
    builtin.filecontent:
      pattern: "Eclipse Public License 1.0"
  tag: ["Eclipse Public License 1.0"]
- ruleID: bsd-license
  description: "BSD license file"
  when:
    builtin.filecontent:
      pattern: "BSD License"
  tag: ["BSD License"]
- ruleID: pd-license
  description: "Public domain license file"
  when:
    builtin.filecontent:
      pattern: "Public Domain License"
  tag: ["Public Domain License"]
`

// converted from https://github.com/windup/windup/blob/master/rules-java/api/src/main/java/org/jboss/windup/rules/apps/java/
// TODO: scope hard-coded IP to .java, pom.xml, .properties files
const java_rules = `
- ruleID: hardcoded-ip-address
  description: "Hardcoded IP Address\nWhen migrating environments, hard-coded IP addresses may need to be modified or eliminated."
  labels:
  - konveyor.io/target=cloud-readiness
  when:
    builtin.filecontent:
      pattern: ([0-9]{1,3}\.){3}[0-9]{1,3}
  category: mandatory
  effort: 1
  message: "When migrating environments, hard-coded IP addresses may need to be modified or eliminated."
- ruleID: discover-properties-file
  description: "Properties file"
  when:
    builtin.file:
      pattern: "^.*\\.properties$"
  tag: ["Properties"]
- ruleID: discover-manifest-file
  description: "Manifest file"
  when:
    builtin.file:
      pattern: "MANIFEST.MF"
  tag: ["Manifest"]
- ruleID: discover-java-files
  description: "Java source files"
  when:
    builtin.file:
      pattern: "*.java"
  tag: ["Java Source"]
- ruleID: discover-maven-xml
  description: "Maven XML file"
  when:
    builtin.file:
      pattern: "pom.xml"
  tag: ["Maven XML"]
`

const java_ee_rules = `
- ruleID: windup-discover-ejb-configuration
  tag: ["EJB XML"]
  when:
    builtin.xml:
      xpath: "/(jboss:ejb-jar or ejb-jar)"
- ruleID: windup-discover-spring-configuration
  tag: ["Spring XML"]
  when:
    builtin.xml:
      xpath: "/beans"
- ruleID: windup-discover-jpa-configuration
  tag: ["JPA XML"]
  when:
    or:
      - builtin.xml:
          xpath: '/persistence[boolean(namespace-uri(/persistence)="http://java.sun.com/xml/ns/persistence")]'
      - builtin.xml:
          xpath: '/persistence[boolean(namespace-uri(/persistence)="http://xmlns.jcp.org/xml/ns/persistence")]'
      - builtin.xml:
          xpath: '/persistence[boolean(namespace-uri(/persistence)="https://jakarta.ee/xml/ns/persistence")]'
- ruleID: windup-discover-web-configuration
  tag: ["Web XML"]
  when:
    # TODO extract version as in rules-java-ee/addon/src/main/java/org/jboss/windup/rules/apps/javaee/rules/DiscoverWebXmlRuleProvider.java
    builtin.xml:
      xpath: /web-app
`

func GetDiscoveryRules() string {
	rules := []string{}
	rules = append(rules, strings.Trim(license_rules, "\n"))
	rules = append(rules, strings.Trim(java_rules, "\n"))
	rules = append(rules, strings.Trim(java_ee_rules, "\n"))
	return strings.Join(rules, "\n")
}

func GetDiscoveryRuleset() string {
	return `
name: discovery-rules
labels:
- discovery
`
}
