package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SastAnalyzerCoverageTest {

    @Test
    void analyze_nullContent_returnsEmpty() {
        List<Map<String, Object>> result = SastAnalyzer.analyze(null, "test.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_emptyContent_returnsEmpty() {
        List<Map<String, Object>> result = SastAnalyzer.analyze("", "test.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_sqlInjection_detected() {
        String code = "Statement stmt = conn.createStatement();\nString q = \"SELECT * FROM users WHERE id=\" + input;";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "AuthService.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-89");
    }

    @Test
    void analyze_commandInjection_detected() {
        String code = "Runtime.getRuntime().exec(userInput);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Service.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-78");
    }

    @Test
    void analyze_xss_detected() {
        String code = "document.write(userInput);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "App.js");
        assertThat(result).isNotEmpty();
        boolean foundXss = result.stream().anyMatch(f -> f.get("cwe").equals("CWE-79"));
        assertThat(foundXss).isTrue();
    }

    @Test
    void analyze_ssrf_detected() {
        String code = "URL url = new URL(base + userInput);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Client.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-918");
    }

    @Test
    void analyze_pathTraversal_detected() {
        String code = "new File(baseDir + userInput);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "FileService.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-22");
    }

    @Test
    void analyze_deserialization_detected() {
        String code = "ObjectInputStream ois = new ObjectInputStream(is);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Deserialize.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-502");
    }

    @Test
    void analyze_xxe_detected() {
        String code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "XmlParser.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-611");
    }

    @Test
    void analyze_weakCrypto_detected() {
        String code = "MessageDigest.getInstance(\"MD5\");";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Crypto.java");
        assertThat(result).isNotEmpty();
        boolean foundWeak = result.stream().anyMatch(f -> f.get("cwe").equals("CWE-327"));
        assertThat(foundWeak).isTrue();
    }

    @Test
    void analyze_hardcodedPassword_detected() {
        String code = "String password = \"supersecret123\";";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Config.java");
        assertThat(result).isNotEmpty();
        boolean foundCred = result.stream().anyMatch(f -> f.get("cwe").equals("CWE-798"));
        assertThat(foundCred).isTrue();
    }

    @Test
    void analyze_debugMode_detected() {
        String code = "debug = true;\nconsole.log('debugging');";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "App.js");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_insecureRandom_detected() {
        String code = "new Random().nextInt(100);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Token.java");
        assertThat(result).isNotEmpty();
        boolean foundRandom = result.stream().anyMatch(f -> f.get("cwe").equals("CWE-330"));
        assertThat(foundRandom).isTrue();
    }

    @Test
    void analyze_nosqlInjection_detected() {
        String code = "db.collection.find({$where: userInput});";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "NoSql.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-943");
    }

    @Test
    void analyze_verboseError_detected() {
        String code = "e.printStackTrace();";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "ErrorHandler.java");
        assertThat(result).isNotEmpty();
        boolean foundVerbose = result.stream().anyMatch(f -> f.get("cwe").equals("CWE-209"));
        assertThat(foundVerbose).isTrue();
    }

    @Test
    void analyze_insecureDeserialization_python_detected() {
        String code = "pickle.loads(data);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "app.py");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_noVuln_returnsEmpty() {
        String code = "System.out.println(\"Hello World\");";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Main.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_nullFileName_handled() {
        String code = "Runtime.getRuntime().exec(cmd);";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, null);
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("file")).isEqualTo("unknown");
    }

    @Test
    void analyze_multipleVulns_found() {
        String code = """
                String q = "SELECT * FROM users WHERE id=" + input;
                Runtime.getRuntime().exec(cmd);
                MessageDigest.getInstance("MD5");
                """;
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Multi.java");
        assertThat(result.size()).isGreaterThanOrEqualTo(3);
    }

    @Test
    void analyze_lineNumber_correct() {
        String code = "line1\nline2\nRuntime.getRuntime().exec(cmd);\nline4";
        List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Test.java");
        assertThat(result).isNotEmpty();
        assertThat((Integer) result.get(0).get("line")).isEqualTo(3);
    }
}
