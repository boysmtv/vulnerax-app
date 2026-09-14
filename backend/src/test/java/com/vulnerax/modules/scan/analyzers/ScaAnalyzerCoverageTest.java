package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScaAnalyzerCoverageTest {

    @Test
    void analyze_nullContent_returnsEmpty() {
        List<Map<String, Object>> result = ScaAnalyzer.analyze(null, "pom.xml");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_emptyContent_returnsEmpty() {
        List<Map<String, Object>> result = ScaAnalyzer.analyze("", "pom.xml");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_maven_vulnDep_found() {
        String pom = """
                <project>
                  <dependencies>
                    <dependency>
                      <artifactId>log4j-core</artifactId>
                      <version>2.14.1</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cve")).isEqualTo("CVE-2021-44228");
    }

    @Test
    void analyze_maven_safeDep_empty() {
        String pom = """
                <project>
                  <dependencies>
                    <dependency>
                      <artifactId>log4j-core</artifactId>
                      <version>2.17.1</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_npm_vulnDep_found() {
        String pkg = """
                {
                  "dependencies": {
                    "lodash": "4.17.20"
                  }
                }
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cve")).isEqualTo("CVE-2020-8203");
    }

    @Test
    void analyze_npm_withCaret_handled() {
        String pkg = """
                {
                  "dependencies": {
                    "lodash": "^4.17.20"
                  }
                }
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_pip_vulnDep_found() {
        String req = "Django==3.2.5\nflask==2.0.0";
        List<Map<String, Object>> result = ScaAnalyzer.analyze(req, "requirements.txt");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cve")).isEqualTo("CVE-2021-35042");
    }

    @Test
    void analyze_pip_commentLines_skipped() {
        String req = "# Django==3.2.5\nflask==2.0.0";
        List<Map<String, Object>> result = ScaAnalyzer.analyze(req, "requirements.txt");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_goMod_returnsEmpty() {
        String go = "module example.com/app\nrequire github.com/gin-gonic/gin v1.7.0";
        List<Map<String, Object>> result = ScaAnalyzer.analyze(go, "go.mod");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_generic_findsVuln() {
        String content = "using log4j 2.14.1 in our app";
        List<Map<String, Object>> result = ScaAnalyzer.analyze(content, "readme.md");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_springCore_vuln() {
        String pom = """
                <artifactId>spring-core</artifactId>
                <version>5.3.18</version>
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cve")).isEqualTo("CVE-2022-22965");
    }

    @Test
    void analyze_express_vuln() {
        String pkg = """
                {
                  "dependencies": {
                    "express": "4.17.1"
                  }
                }
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_findingFields_complete() {
        String pkg = """
                {
                  "dependencies": {
                    "axios": "0.21.1"
                  }
                }
                """;
        List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
        assertThat(result).isNotEmpty();
        Map<String, Object> f = result.get(0);
        assertThat(f).containsKey("component");
        assertThat(f).containsKey("installedVersion");
        assertThat(f).containsKey("cve");
        assertThat(f).containsKey("severity");
        assertThat(f).containsKey("cvss");
        assertThat(f).containsKey("kev");
        assertThat(f).containsKey("epss");
        assertThat(f).containsKey("file");
        assertThat(f).containsKey("fixedVersion");
        assertThat(f).containsKey("title");
    }

    @Test
    void analyze_nullFileName_handled() {
        String content = "using log4j 2.14.1";
        List<Map<String, Object>> result = ScaAnalyzer.analyze(content, null);
        assertThat(result).isNotNull();
    }
}
