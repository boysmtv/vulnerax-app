package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@DisplayName("Security Analyzers — Comprehensive Unit Tests")
class AnalyzersTest {

    // ════════════════════════════════════════════════════════════════
    //  SAST ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("SastAnalyzer")
    class SastAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null content")
        void nullContent_returnsEmpty() {
            List<Map<String, Object>> result = SastAnalyzer.analyze(null, "test.java");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty content")
        void emptyContent_returnsEmpty() {
            List<Map<String, Object>> result = SastAnalyzer.analyze("", "test.java");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for clean code")
        void cleanCode_returnsEmpty() {
            String clean = """
                    public class SafeApp {
                        public void handle(String input) {
                            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                            ps.setString(1, input);
                            ps.execute();
                        }
                    }
                    """;
            List<Map<String, Object>> result = SastAnalyzer.analyze(clean, "SafeApp.java");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects SQL injection via string concatenation")
        void detectsSqlInjection() {
            String code = "Statement stmt = conn.createStatement();\n"
                    + "ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE name='\" + input + \"'\");";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "UserDao.java");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-89"));
            assertThat(result).anyMatch(f -> ((String) f.get("severity")).contains("CRITICAL"));
        }

        @Test
        @DisplayName("detects command injection via Runtime.exec")
        void detectsCommandInjection() {
            String code = "Runtime.getRuntime().exec(userInput);";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Runner.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-78"));
        }

        @Test
        @DisplayName("detects XSS via innerHTML assignment")
        void detectsXss() {
            String code = "document.getElementById('output').innerHTML = userInput;";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "app.js");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-79"));
        }

        @Test
        @DisplayName("detects hardcoded credential")
        void detectsHardcodedCredential() {
            String code = "String password = \"supersecret123\";";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Config.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-798"));
        }

        @Test
        @DisplayName("detects insecure deserialization")
        void detectsInsecureDeserialization() {
            String code = "ObjectInputStream ois = new ObjectInputStream(inputStream);\n"
                    + "Object obj = ois.readObject();";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Loader.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-502"));
        }

        @Test
        @DisplayName("detects SSRF via URL constructor")
        void detectsSsrf() {
            String code = "URL url = new URL(userInput + \"/api\");\n"
                    + "HttpURLConnection conn = (HttpURLConnection) url.openConnection();";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Fetcher.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-918"));
        }

        @Test
        @DisplayName("detects path traversal via new File")
        void detectsPathTraversal() {
            String code = "File f = new File(baseDir + userInput);";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "FileHandler.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-22"));
        }

        @Test
        @DisplayName("detects XXE via DocumentBuilderFactory")
        void detectsXxe() {
            String code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "XmlParser.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-611"));
        }

        @Test
        @DisplayName("detects weak crypto MD5")
        void detectsWeakCrypto() {
            String code = "MessageDigest.getInstance(\"MD5\");";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Crypto.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-327"));
        }

        @Test
        @DisplayName("detects insecure random")
        void detectsInsecureRandom() {
            String code = "Random rand = new Random();\nint token = rand.nextInt(999999);";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "TokenGen.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-330"));
        }

        @Test
        @DisplayName("detects multiple vulnerabilities in same file")
        void detectsMultipleVulnerabilities() {
            String code = """
                    String password = "admin123";
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    Random rand = new Random();
                    """;
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "BadCode.java");
            assertThat(result.size()).isGreaterThanOrEqualTo(3);
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-89"));
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-798"));
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-327"));
        }

        @Test
        @DisplayName("uses unknown when fileName is null")
        void nullFileName_usesUnknown() {
            String code = "MessageDigest.getInstance(\"MD5\");";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, null);
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("file")).isEqualTo("unknown");
        }

        @Test
        @DisplayName("detects verbose error via printStackTrace")
        void detectsVerboseError() {
            String code = "catch (Exception e) { e.printStackTrace(); }";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Handler.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-209"));
        }

        @Test
        @DisplayName("detects debug mode enabled")
        void detectsDebugMode() {
            String code = "debug = true;";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "config.py");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-489"));
        }

        @Test
        @DisplayName("detects JWT none algorithm")
        void detectsJwtNoneAlgorithm() {
            String code = "algorithm = \"none\";";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Auth.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-347"));
        }

        @Test
        @DisplayName("detects BOLA via @PathVariable")
        void detectsBola() {
            String code = "@GetMapping(\"/users/{id}\")\npublic User getUser(@PathVariable Long id) {";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "UserController.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-639"));
        }

        @Test
        @DisplayName("detects mass assignment via @RequestBody")
        void detectsMassAssignment() {
            String code = "@PostMapping(\"/users\")\npublic User create(@RequestBody User user) {";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "UserController.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-915"));
        }

        @Test
        @DisplayName("detects unsafe file upload via MultipartFile")
        void detectsUnsafeFileUpload() {
            String code = "String name = MultipartFile.getOriginalFilename();";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Upload.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-434"));
        }

        @Test
        @DisplayName("detects hardcoded API key")
        void detectsApiKey() {
            String code = "api_key = \"AKIAIOSFODNN7EXAMPLE12\"";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "config.py");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-798"));
        }

        @Test
        @DisplayName("detects process builder command injection")
        void detectsProcessBuilder() {
            String code = "ProcessBuilder pb = new ProcessBuilder(userInput);";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Runner.java");
            assertThat(result).anyMatch(f -> f.get("cwe").equals("CWE-78"));
        }

        @Test
        @DisplayName("line number is correctly calculated")
        void lineNumberCorrect() {
            String code = "line1\nline2\nline3\nMessageDigest.getInstance(\"MD5\");\nline5";
            List<Map<String, Object>> result = SastAnalyzer.analyze(code, "Test.java");
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("line")).isEqualTo(4);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  SCA ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("ScaAnalyzer")
    class ScaAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null content")
        void nullContent_returnsEmpty() {
            List<Map<String, Object>> result = ScaAnalyzer.analyze(null, "pom.xml");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty content")
        void emptyContent_returnsEmpty() {
            List<Map<String, Object>> result = ScaAnalyzer.analyze("", "pom.xml");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects vulnerable log4j in Maven pom.xml")
        void detectsVulnerableLog4jMaven() {
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
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2021-44228"));
            assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
        }

        @Test
        @DisplayName("detects vulnerable log4j 2.15.0 in pom.xml")
        void detectsVulnerableLog4j215() {
            String pom = """
                    <project>
                      <dependencies>
                        <artifactId>log4j-core</artifactId>
                        <version>2.15.0</version>
                      </dependencies>
                    </project>
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2021-45046"));
        }

        @Test
        @DisplayName("detects vulnerable spring-core in pom.xml")
        void detectsVulnerableSpring() {
            String pom = """
                    <project>
                      <dependencies>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.18</version>
                      </dependencies>
                    </project>
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2022-22965"));
        }

        @Test
        @DisplayName("no findings for safe Maven versions")
        void safeMavenVersions_noFindings() {
            String pom = """
                    <project>
                      <dependencies>
                        <artifactId>log4j-core</artifactId>
                        <version>2.17.1</version>
                      </dependencies>
                    </project>
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects vulnerable lodash in package.json")
        void detectsVulnerableLodashNpm() {
            String pkg = """
                    {
                      "dependencies": {
                        "lodash": "4.17.20"
                      }
                    }
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2020-8203"));
        }

        @Test
        @DisplayName("detects vulnerable axios in package.json")
        void detectsVulnerableAxiosNpm() {
            String pkg = """
                    {
                      "dependencies": {
                        "axios": "0.21.1"
                      }
                    }
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2020-28168"));
        }

        @Test
        @DisplayName("detects vulnerable express in package.json")
        void detectsVulnerableExpressNpm() {
            String pkg = """
                    {
                      "dependencies": {
                        "express": "4.17.1"
                      }
                    }
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2022-24999"));
        }

        @Test
        @DisplayName("no findings for safe npm versions")
        void safeNpmVersions_noFindings() {
            String pkg = """
                    {
                      "dependencies": {
                        "lodash": "4.17.21",
                        "axios": "0.21.4"
                      }
                    }
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects vulnerable Django in requirements.txt")
        void detectsVulnerableDjangoPip() {
            String req = "Django==3.2.5\nflask==2.0.0\nrequests==2.28.0";
            List<Map<String, Object>> result = ScaAnalyzer.analyze(req, "requirements.txt");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2021-35042"));
        }

        @Test
        @DisplayName("no findings for safe pip versions")
        void safePipVersions_noFindings() {
            String req = "Django==3.2.14\nflask==2.0.0";
            List<Map<String, Object>> result = ScaAnalyzer.analyze(req, "requirements.txt");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty for go.mod (not yet implemented)")
        void goMod_returnsEmpty() {
            String goMod = "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1";
            List<Map<String, Object>> result = ScaAnalyzer.analyze(goMod, "go.mod");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("correct finding structure")
        void findingStructure() {
            String pom = """
                    <artifactId>log4j-core</artifactId>
                    <version>2.14.1</version>
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, "pom.xml");
            assertThat(result).isNotEmpty();
            Map<String, Object> finding = result.get(0);
            assertThat(finding).containsKey("component");
            assertThat(finding).containsKey("coords");
            assertThat(finding).containsKey("installedVersion");
            assertThat(finding).containsKey("cve");
            assertThat(finding).containsKey("severity");
            assertThat(finding).containsKey("cvss");
            assertThat(finding).containsKey("kev");
            assertThat(finding).containsKey("epss");
            assertThat(finding).containsKey("fixedVersion");
            assertThat(finding).containsKey("dependencyType");
        }

        @Test
        @DisplayName("null fileName defaults to unknown")
        void nullFileName_defaultsToUnknown() {
            String pom = "<artifactId>log4j-core</artifactId>\n<version>2.14.1</version>";
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pom, null);
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("file")).isEqualTo("unknown");
        }

        @Test
        @DisplayName("strips caret/tilde from npm versions")
        void stripsNpmPrefixes() {
            String pkg = """
                    {
                      "dependencies": {
                        "lodash": "^4.17.20"
                      }
                    }
                    """;
            List<Map<String, Object>> result = ScaAnalyzer.analyze(pkg, "package.json");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("cve").equals("CVE-2020-8203"));
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  SECRET ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("SecretAnalyzer")
    class SecretAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null content")
        void nullContent_returnsEmpty() {
            List<Map<String, Object>> result = SecretAnalyzer.analyze(null, "config.yml");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty content")
        void emptyContent_returnsEmpty() {
            List<Map<String, Object>> result = SecretAnalyzer.analyze("", "config.yml");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty for clean content")
        void cleanContent_returnsEmpty() {
            String code = "public class App {\n    int x = 42;\n}";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(code, "App.java");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects AWS access key")
        void detectsAwsAccessKey() {
            String content = "access_key_id = AKIAIOSFODNN7EXAMPLE";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.properties");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("rule").equals("AWS Access Key"));
            assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("HIGH"));
        }

        @Test
        @DisplayName("detects AWS secret key")
        void detectsAwsSecretKey() {
            String content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.properties");
            assertThat(result).anyMatch(f -> f.get("rule").equals("AWS Secret Key"));
        }

        @Test
        @DisplayName("detects RSA private key")
        void detectsPrivateKey() {
            String content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "server.pem");
            assertThat(result).isNotEmpty();
            assertThat(result).anyMatch(f -> f.get("rule").equals("Private Key"));
            assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
        }

        @Test
        @DisplayName("detects generic API key")
        void detectsGenericApiKey() {
            String content = "api_key = \"abcdefghij1234567890abcdefghij\"";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.yml");
            assertThat(result).anyMatch(f -> f.get("rule").equals("Generic API Key"));
        }

        @Test
        @DisplayName("detects JWT secret")
        void detectsJwtSecret() {
            String content = "jwt_secret = \"mySuperSecretJwtKey12345678\"";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "application.properties");
            assertThat(result).anyMatch(f -> f.get("rule").equals("JWT Secret"));
        }

        @Test
        @DisplayName("detects Firebase API key")
        void detectsFirebaseKey() {
            String content = "firebaseKey = AIzaSyDdExample1234567890abcdefghijklmnopq";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.json");
            assertThat(result).anyMatch(f -> f.get("rule").equals("Firebase Key"));
        }

        @Test
        @DisplayName("detects multiple secrets in one file")
        void detectsMultipleSecrets() {
            String content = """
                    access_key_id = AKIAIOSFODNN7EXAMPLE
                    jwt_secret = "superSecretJwtKey12345678"
                    -----BEGIN PRIVATE KEY-----
                    MIIEvQIBADANBg...
                    -----END PRIVATE KEY-----
                    """;
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "leaked.yml");
            assertThat(result.size()).isGreaterThanOrEqualTo(3);
        }

        @Test
        @DisplayName("masks matched secret value")
        void masksMatchedValue() {
            String content = "access_key_id = AKIAIOSFODNN7EXAMPLE";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.properties");
            assertThat(result).isNotEmpty();
            String masked = (String) result.get(0).get("match");
            assertThat(masked).contains("****");
            assertThat(masked).doesNotContain("IOSFODNN7");
        }

        @Test
        @DisplayName("null fileName uses unknown")
        void nullFileName_usesUnknown() {
            String content = "access_key_id = AKIAIOSFODNN7EXAMPLE";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, null);
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("file")).isEqualTo("unknown");
        }

        @Test
        @DisplayName("respects 20 finding limit")
        void respectsFindingLimit() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 25; i++) {
                sb.append("access_key_id = AKIAIOSFODNN7EXAMP").append(i).append("\n");
            }
            List<Map<String, Object>> result = SecretAnalyzer.analyze(sb.toString(), "keys.txt");
            assertThat(result.size()).isLessThanOrEqualTo(20);
        }

        @Test
        @DisplayName("calculates line number correctly")
        void calculatesLineNumber() {
            String content = "line1\nline2\nline3\naccess_key_id = AKIAIOSFODNN7EXAMPLE\nline5";
            List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "test.properties");
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("line")).isEqualTo(4);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  IAC ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("IaCAnalyzer")
    class IaCAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null content")
        void nullContent_returnsEmpty() {
            List<Map<String, Object>> result = IaCAnalyzer.analyze(null, "main.tf");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty content")
        void emptyContent_returnsEmpty() {
            List<Map<String, Object>> result = IaCAnalyzer.analyze("", "main.tf");
            assertThat(result).isEmpty();
        }

        // --- Terraform ---
        @Nested
        @DisplayName("Terraform analysis")
        class TerraformTest {

            @Test
            @DisplayName("detects public S3 ACL")
            void detectsPublicS3Acl() {
                String tf = "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "s3.tf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("S3 Public ACL"));
                assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
            }

            @Test
            @DisplayName("detects unencrypted S3 bucket")
            void detectsUnencryptedS3() {
                String tf = "resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"my-bucket\"\n}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "s3.tf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("S3 No Encryption"));
            }

            @Test
            @DisplayName("detects publicly accessible RDS")
            void detectsPublicRds() {
                String tf = "resource \"aws_db_instance\" \"db\" {\n  publicly_accessible = true\n}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "rds.tf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("RDS Publicly Accessible"));
            }

            @Test
            @DisplayName("detects open security group 0.0.0.0/0")
            void detectsOpenSecurityGroup() {
                String tf = "resource \"aws_security_group\" \"sg\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "sg.tf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Security Group Open"));
            }

            @Test
            @DisplayName("detects IAM wildcard action")
            void detectsIamWildcard() {
                String tf = "resource \"aws_iam_policy\" \"p\" {\n  \"Effect\" = \"Allow\"\n  \"Action\" = \"*\"\n}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "iam.tf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("IAM Wildcard Action"));
            }

            @Test
            @DisplayName("clean terraform returns no critical findings")
            void cleanTerraform_returnsNoCritical() {
                String tf = """
                        resource "aws_s3_bucket" "data" {
                          bucket = "my-bucket"
                          server_side_encryption_configuration {}
                          logging {}
                        }
                        """;
                List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "s3.tf");
                assertThat(result).noneMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
            }
        }

        // --- Kubernetes ---
        @Nested
        @DisplayName("Kubernetes analysis")
        class KubernetesTest {

            @Test
            @DisplayName("detects privileged pod")
            void detectsPrivilegedPod() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("K8s Privileged Pod"));
            }

            @Test
            @DisplayName("detects host network")
            void detectsHostNetwork() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers: []";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("K8s Host Network"));
            }

            @Test
            @DisplayName("detects host PID")
            void detectsHostPid() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true\n  containers: []";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("K8s Host PID"));
            }

            @Test
            @DisplayName("detects default root user")
            void detectsDefaultRoot() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers: []";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("K8s Default Root User"));
            }

            @Test
            @DisplayName("detects no resource limits")
            void detectsNoResourceLimits() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("K8s No Resource Limits"));
            }

            @Test
            @DisplayName("detects SA token auto-mount")
            void detectsSaTokenAutoMount() {
                String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers: []";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("SA Token Auto-mount"));
            }

            @Test
            @DisplayName("detects LoadBalancer exposure")
            void detectsLoadBalancer() {
                String k8s = "apiVersion: v1\nkind: Service\nspec:\n  type: LoadBalancer\n  containers: []";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "svc.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("LoadBalancer Exposed"));
            }
        }

        // --- Dockerfile ---
        @Nested
        @DisplayName("Dockerfile analysis")
        class DockerfileTest {

            @Test
            @DisplayName("detects no version pin")
            void detectsNoVersionPin() {
                String df = "FROM node:latest\nRUN npm install";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("No Version Pin"));
            }

            @Test
            @DisplayName("detects COPY . entire context")
            void detectsCopyDot() {
                String df = "FROM node:18\nCOPY . /app";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("COPY . (entire context)"));
            }

            @Test
            @DisplayName("detects ADD from URL")
            void detectsAddFromUrl() {
                String df = "FROM node:18\nADD https://example.com/file.tar.gz /app/";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("ADD from URL"));
            }

            @Test
            @DisplayName("detects chmod 777")
            void detectsChmod777() {
                String df = "FROM node:18\nRUN chmod 777 /app";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("chmod 777"));
            }

            @Test
            @DisplayName("detects secret in ENV")
            void detectsSecretInEnv() {
                String df = "FROM node:18\nENV password=supersecret";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Secret in ENV"));
            }

            @Test
            @DisplayName("detects dangerous port exposed")
            void detectsDangerousPort() {
                String df = "FROM node:18\nEXPOSE 22";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Dangerous Port Exposed"));
            }

            @Test
            @DisplayName("detects no USER instruction")
            void detectsNoUser() {
                String df = "FROM node:18\nRUN npm install";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("No USER Instruction"));
            }
        }

        // --- CloudFormation ---
        @Nested
        @DisplayName("CloudFormation analysis")
        class CloudFormationTest {

            @Test
            @DisplayName("detects publicly accessible resource")
            void detectsPublicResource() {
                String cf = "{\"AWSTemplateFormatVersion\": \"2010-09-09\", \"Resources\": {\"PubliclyAccessible\": true}}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(cf, "template.yaml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("CloudFormation: Public Resource"));
            }

            @Test
            @DisplayName("detects open security group in CF")
            void detectsCfOpenSg() {
                String cf = "{\"AWSTemplateFormatVersion\": \"2010-09-09\", \"Type\": \"AWS::EC2::SecurityGroup\", \"Properties\": {}, \"SecurityGroupIngress\": {}, \"CidrIp\": \"0.0.0.0/0\"}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(cf, "template.json");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Open Security Group"));
            }
        }

        // --- Generic ---
        @Nested
        @DisplayName("Generic config analysis")
        class GenericTest {

            @Test
            @DisplayName("detects hardcoded password in generic config")
            void detectsHardcodedPassword() {
                String cfg = "database:\n  password: admin123\n  host: localhost";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(cfg, "config.yml");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Hardcoded Password"));
            }

            @Test
            @DisplayName("detects open network rule")
            void detectsOpenNetwork() {
                String cfg = "firewall:\n  rule: 0.0.0.0/0";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(cfg, "firewall.conf");
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Open Network Rule"));
            }

            @Test
            @DisplayName("no findings for masked password")
            void maskedPassword_noFinding() {
                String cfg = "password = ${DB_PASSWORD}";
                List<Map<String, Object>> result = IaCAnalyzer.analyze(cfg, "config.yml");
                assertThat(result).noneMatch(f -> f.get("title").toString().contains("Hardcoded Password"));
            }
        }

        @Test
        @DisplayName("unknown type returns generic scan complete")
        void unknownType_returnsScanComplete() {
            String content = "some random config without security issues";
            List<Map<String, Object>> result = IaCAnalyzer.analyze(content, "random.txt");
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("title").toString()).contains("IaC Scan Complete");
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  CONTAINER ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("ContainerAnalyzer")
    class ContainerAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null target")
        void nullTarget_returnsEmpty() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze(null, null);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty target")
        void emptyTarget_returnsEmpty() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("", null);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("detects vulnerable base image nginx:1.18")
        void detectsVulnerableNginx() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.18", null);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Vulnerable Base Image"));
        }

        @Test
        @DisplayName("detects vulnerable base image node:14")
        void detectsVulnerableNode() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("node:14", null);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Vulnerable Base Image"));
        }

        @Test
        @DisplayName("detects vulnerable base image python:3.8")
        void detectsVulnerablePython() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("python:3.8", null);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Vulnerable Base Image"));
        }

        @Test
        @DisplayName("safe image no vulnerable base finding")
        void safeImage_noVulnerableBase() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25.3", null);
            assertThat(result).noneMatch(f -> f.get("title").toString().contains("Vulnerable Base Image"));
        }

        @Test
        @DisplayName("detects running as root")
        void detectsRunningAsRoot() {
            String config = "User: root";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Running as Root"));
        }

        @Test
        @DisplayName("detects privileged container")
        void detectsPrivilegedContainer() {
            String config = "\"privileged\":true";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Privileged Container"));
            assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
        }

        @Test
        @DisplayName("detects privileged via docker-compose syntax")
        void detectsPrivilegedDockerCompose() {
            String config = "privileged: true";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Privileged Container"));
        }

        @Test
        @DisplayName("detects secret in container config")
        void detectsSecretInConfig() {
            String config = "environment:\n  - MYSQL_ROOT_PASSWORD=secret123";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("mysql:5.7", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Secret in Container Config"));
        }

        @Test
        @DisplayName("detects host network mode")
        void detectsHostNetwork() {
            String config = "network_mode: host";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Host Network Mode"));
        }

        @Test
        @DisplayName("detects host PID namespace")
        void detectsHostPid() {
            String config = "pid: host";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Host PID Namespace"));
        }

        @Test
        @DisplayName("detects dangerous capabilities")
        void detectsDangerousCapabilities() {
            String config = "cap_add:\n  - SYS_ADMIN";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Dangerous Capabilities"));
        }

        @Test
        @DisplayName("detects writable root filesystem")
        void detectsWritableRoot() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", "");
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("Writable Root Filesystem"));
        }

        @Test
        @DisplayName("read-only root filesystem has no writable finding")
        void readOnlyRoot_noWritableFinding() {
            String config = "read_only: true";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
            assertThat(result).noneMatch(f -> f.get("title").toString().contains("Writable Root Filesystem"));
        }

        @Test
        @DisplayName("detects latest tag")
        void detectsLatestTag() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("myapp:latest", null);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("latest"));
        }

        @Test
        @DisplayName("image without tag is treated as latest")
        void imageWithoutTag_treatedAsLatest() {
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("myapp", null);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("latest"));
        }

        @Test
        @DisplayName("detects apt cache not cleaned")
        void detectsAptCacheNotCleaned() {
            String config = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
            assertThat(result).anyMatch(f -> f.get("title").toString().contains("apt cache not cleaned"));
        }

            @Test
            @DisplayName("detects Dockerfile secret in ENV/ARG")
            void detectsDockerfileSecretInEnvArg() {
                String config = "FROM ubuntu:22.04\nRUN echo hi\nENV password=secret123";
                List<Map<String, Object>> result = ContainerAnalyzer.analyze("ubuntu:22.04", config);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Secret in Container Config: password"));
            }

        @Test
        @DisplayName("clean image returns no critical findings")
        void cleanImage_noCritical() {
            String config = "read_only: true\nnetwork_mode: bridge";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25.3", config);
            assertThat(result).noneMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
        }

        @Test
        @DisplayName("safe image with good config returns scan complete")
        void safeImageGoodConfig_returnsScanComplete() {
            String config = "read_only: true";
            List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.25.3", config);
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("title").toString()).contains("No Critical Issue");
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  MOBILE ANALYZER
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("MobileAnalyzer")
    class MobileAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null target")
        void nullTarget_returnsEmpty() {
            List<Map<String, Object>> result = MobileAnalyzer.analyze(null, null);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("non-mobile file returns info finding")
        void nonMobileFile_returnsInfoFinding() {
            List<Map<String, Object>> result = MobileAnalyzer.analyze("app.exe", null);
            assertThat(result).isNotEmpty();
            assertThat(result.get(0).get("title").toString()).contains("Not a Mobile Artifact");
        }

        // --- APK ---
        @Nested
        @DisplayName("APK analysis")
        class ApkTest {

            @Test
            @DisplayName("detects allowBackup enabled")
            void detectsAllowBackup() {
                String cfg = "allowBackup=true";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("allowBackup Enabled"));
            }

            @Test
            @DisplayName("detects debuggable app")
            void detectsDebuggable() {
                String cfg = "debuggable=true";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Debuggable"));
                assertThat(result).anyMatch(f -> ((String) f.get("severity")).equals("CRITICAL"));
            }

            @Test
            @DisplayName("detects cleartext traffic allowed")
            void detectsCleartextTraffic() {
                String cfg = "usesCleartextTraffic=true";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Cleartext Traffic Allowed"));
            }

            @Test
            @DisplayName("detects exported component")
            void detectsExportedComponent() {
                String cfg = "exported=true";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Exported Component"));
            }

            @Test
            @DisplayName("detects JavaScript in WebView")
            void detectsJavascriptInWebView() {
                String cfg = "setJavaScriptEnabled(true)";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("JavaScript in WebView"));
            }

            @Test
            @DisplayName("detects file access in WebView")
            void detectsFileAccessInWebView() {
                String cfg = "setAllowFileAccess(true)";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("File Access in WebView"));
            }

            @Test
            @DisplayName("detects deep link without verification")
            void detectsDeepLinkWithoutVerification() {
                String cfg = "intent-filter\nandroid.intent.action.VIEW\nallowBackup=false";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Deep Link without Verification"));
            }

            @Test
            @DisplayName("detects hardcoded API key")
            void detectsHardcodedApiKey() {
                String cfg = "api_key = \"sk-1234567890abcdef\"";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Hardcoded api_key"));
            }

            @Test
            @DisplayName("detects external storage usage")
            void detectsExternalStorage() {
                String cfg = "getExternalFilesDir";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("External Storage Usage"));
            }

            @Test
            @DisplayName("detects weak crypto algorithm")
            void detectsWeakCrypto() {
                String cfg = "AES/ECB/PKCS5Padding";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Weak Crypto Algorithm"));
            }

            @Test
            @DisplayName("detects no root detection")
            void detectsNoRootDetection() {
                String cfg = "some basic config";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("No Root Detection"));
            }

            @Test
            @DisplayName("detects debug logging")
            void detectsDebugLogging() {
                String cfg = "Log.d(TAG, \"user data\");";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Debug Logging in Production"));
            }

            @Test
            @DisplayName("clean APK returns scan complete")
            void cleanApk_returnsScanComplete() {
                String cfg = "allowBackup=false\nisRooted\nnetworkSecurityConfig";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("secure.apk", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("APK Scan Complete"));
            }
        }

        // --- IPA ---
        @Nested
        @DisplayName("IPA analysis")
        class IpaTest {

            @Test
            @DisplayName("detects ATS disabled")
            void detectsAtsDisabled() {
                String cfg = "NSAppTransportSecurity\nNSAllowsArbitraryLoads=YES";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("ATS Disabled"));
            }

            @Test
            @DisplayName("detects file sharing enabled")
            void detectsFileSharing() {
                String cfg = "UIFileSharingEnabled=YES";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("File Sharing Enabled"));
            }

            @Test
            @DisplayName("detects photo library access")
            void detectsPhotoLibrary() {
                String cfg = "NSPhotoLibraryUsageDescription";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Photo Library Access"));
            }

            @Test
            @DisplayName("no keychain usage detected")
            void detectsNoKeychain() {
                String cfg = "NSAppTransportSecurity config only";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("No Keychain Usage"));
            }

            @Test
            @DisplayName("keychain usage present — no keychain finding")
            void keychainPresent_noFinding() {
                String cfg = "kSecAttrAccessible = kSecAttrAccessibleWhenUnlocked";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", cfg);
                assertThat(result).noneMatch(f -> f.get("title").toString().contains("No Keychain Usage"));
            }

            @Test
            @DisplayName("clean IPA returns scan complete")
            void cleanIpa_returnsScanComplete() {
                String cfg = "kSecAttrAccessible";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("secure.ipa", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("IPA Scan Complete"));
            }
        }

        // --- AAB ---
        @Nested
        @DisplayName("AAB analysis")
        class AabTest {

            @Test
            @DisplayName("detects AAB format and runs APK checks")
            void detectsAabFormatAndRunsApkChecks() {
                String cfg = "debuggable=true";
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.aab", cfg);
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("AAB Format Detected"));
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("Debuggable"));
            }

            @Test
            @DisplayName("AAB without config returns findings")
            void aabWithoutConfig_returnsFindings() {
                List<Map<String, Object>> result = MobileAnalyzer.analyze("app.aab", null);
                assertThat(result).isNotEmpty();
                assertThat(result).anyMatch(f -> f.get("title").toString().contains("AAB Format Detected"));
            }
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  DAST ANALYZER (network-dependent — test entry conditions only)
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("DastAnalyzer")
    class DastAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null target")
        void nullTarget_returnsEmpty() {
            List<Map<String, Object>> result = DastAnalyzer.analyze(null, "scan");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for non-HTTP target")
        void nonHttpTarget_returnsEmpty() {
            List<Map<String, Object>> result = DastAnalyzer.analyze("ftp://example.com", "scan");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty target")
        void emptyTarget_returnsEmpty() {
            List<Map<String, Object>> result = DastAnalyzer.analyze("", "scan");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty for non-http schemes (file:, ssh:)")
        void nonHttpSchemes_returnsEmpty() {
            assertThat(DastAnalyzer.analyze("file:///etc/passwd", "scan")).isEmpty();
            assertThat(DastAnalyzer.analyze("ssh://host", "scan")).isEmpty();
            assertThat(DastAnalyzer.analyze("javascript:void(0)", "scan")).isEmpty();
        }

        @Test
        @DisplayName("trims whitespace from target")
        void trimsWhitespace() {
            assertThat(DastAnalyzer.analyze("  ftp://example.com  ", "scan")).isEmpty();
            assertThat(DastAnalyzer.analyze("  ", "scan")).isEmpty();
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  API ANALYZER (network-dependent — test entry conditions only)
    // ════════════════════════════════════════════════════════════════
    @Nested
    @DisplayName("ApiAnalyzer")
    class ApiAnalyzerTest {

        @Test
        @DisplayName("returns empty list for null target")
        void nullTarget_returnsEmpty() {
            List<Map<String, Object>> result = ApiAnalyzer.analyze(null);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for non-HTTP target")
        void nonHttpTarget_returnsEmpty() {
            List<Map<String, Object>> result = ApiAnalyzer.analyze("ftp://api.example.com");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty list for empty target")
        void emptyTarget_returnsEmpty() {
            List<Map<String, Object>> result = ApiAnalyzer.analyze("");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("returns empty for non-http schemes")
        void nonHttpSchemes_returnsEmpty() {
            assertThat(ApiAnalyzer.analyze("file:///local")).isEmpty();
            assertThat(ApiAnalyzer.analyze("ws://socket")).isEmpty();
        }

        @Test
        @DisplayName("strips trailing slash from target")
        void stripsTrailingSlash() {
            assertThat(ApiAnalyzer.analyze("ftp://host/")).isEmpty();
        }
    }
}
