package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScaAnalyzerTest {

    @Test
    void null_empty() {
        assertThat(ScaAnalyzer.analyze(null, "pom.xml")).isEmpty();
        assertThat(ScaAnalyzer.analyze("", "package.json")).isEmpty();
    }

    @Test
    void maven_match_fields() {
        String pom = "<project><artifactId>log4j-core</artifactId><version>2.14.1</version></project>";
        var out = ScaAnalyzer.analyze(pom, "pom.xml");
        assertThat(out).hasSize(1);
        Map<String, Object> f = out.get(0);
        assertThat(f.get("component")).isEqualTo("log4j");
        assertThat(f.get("coords")).isEqualTo("org.apache.logging.log4j:log4j-core");
        assertThat(f.get("cve")).isEqualTo("CVE-2021-44228");
        assertThat(f.get("severity")).isEqualTo("CRITICAL");
        assertThat(f.get("kev")).isEqualTo(true);
        assertThat(f.get("file")).isEqualTo("pom.xml");
        assertThat(f.get("dependencyType")).isEqualTo("direct");
        assertThat(String.valueOf(f.get("title"))).contains("CVE-2021-44228");
    }

    @Test
    void maven_secondEntry_match() {
        String pom = "<artifactId>log4j-core</artifactId>  <version>2.15.0</version>";
        var out = ScaAnalyzer.analyze(pom, "pom.xml");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("cve")).isEqualTo("CVE-2021-45046");
    }

    @Test
    void maven_noMatch() {
        assertThat(ScaAnalyzer.analyze("<artifactId>log4j-core</artifactId><version>9.9.9</version>", "pom.xml")).isEmpty();
        assertThat(ScaAnalyzer.analyze("<artifactId>other-lib</artifactId><version>2.14.1</version>", "pom.xml")).isEmpty();
        assertThat(ScaAnalyzer.analyze("<project></project>", "pom.xml")).isEmpty();
    }

    @Test
    void npm_matches_and_caretTilde() {
        var out = ScaAnalyzer.analyze("{\"dependencies\":{\"lodash\":\"^4.17.20\"}}", "package.json");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("cve")).isEqualTo("CVE-2020-8203");
        var out2 = ScaAnalyzer.analyze("{\"dependencies\":{\"axios\":\"~0.21.1\"}}", "package.json");
        assertThat(out2).hasSize(1);
        var out3 = ScaAnalyzer.analyze("{\"dependencies\":{\"express\":\"4.17.1\"}}", "package.json");
        assertThat(out3).hasSize(1);
    }

    @Test
    void npm_noMatch() {
        assertThat(ScaAnalyzer.analyze("{\"dependencies\":{\"lodash\":\"4.17.21\"}}", "package.json")).isEmpty();
        assertThat(ScaAnalyzer.analyze("{\"dependencies\":{\"unknown-lib\":\"1.0.0\"}}", "package.json")).isEmpty();
    }

    @Test
    void pip_match_skips() {
        String req = "# comment\n\nDjango==3.2.5\nbadline-without-separator\nflask>=2.0\n";
        var out = ScaAnalyzer.analyze(req, "requirements.txt");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("component")).isEqualTo("django");
    }

    @Test
    void pip_noMatch() {
        assertThat(ScaAnalyzer.analyze("requests==2.28.0\n", "requirements.txt")).isEmpty();
    }

    @Test
    void goMod_empty() {
        assertThat(ScaAnalyzer.analyze("module example.com/app\ngo 1.21\n", "go.mod")).isEmpty();
    }

    @Test
    void generic_match() {
        var out = ScaAnalyzer.analyze("notes: using spring-core version 5.3.18, please upgrade", "notes.md");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("component")).isEqualTo("spring-core");
        assertThat(out.get(0).get("dependencyType")).isEqualTo("generic");
    }

    @Test
    void generic_noMatch() {
        assertThat(ScaAnalyzer.analyze("hello world, nothing here", "notes.md")).isEmpty();
    }

    @Test
    void nullFileName_unknown() {
        var out = ScaAnalyzer.analyze("{\"dependencies\":{\"lodash\":\"4.17.20\"}}", null);
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("file")).isEqualTo("unknown");
    }
}
