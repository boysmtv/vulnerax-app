package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MobileAnalyzerCoverageTest {

    @Test
    void analyze_nullTarget_returnsEmpty() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze(null, null);
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_apk_allowBackup_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", null);
        assertThat(result).isNotEmpty();
        boolean foundBackup = result.stream().anyMatch(f -> f.get("title").toString().contains("allowBackup"));
        assertThat(foundBackup).isTrue();
    }

    @Test
    void analyze_apk_debuggable_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "debuggable=true");
        assertThat(result).isNotEmpty();
        boolean foundDebug = result.stream().anyMatch(f -> f.get("title").toString().contains("Debuggable"));
        assertThat(foundDebug).isTrue();
    }

    @Test
    void analyze_apk_cleartextTraffic_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", null);
        boolean foundCleartext = result.stream().anyMatch(f -> f.get("title").toString().contains("Cleartext"));
        assertThat(foundCleartext).isTrue();
    }

    @Test
    void analyze_apk_exportedComponent_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "exported=true");
        boolean foundExported = result.stream().anyMatch(f -> f.get("title").toString().contains("Exported"));
        assertThat(foundExported).isTrue();
    }

    @Test
    void analyze_apk_javascriptWebView_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "setJavaScriptEnabled(true)");
        boolean foundJs = result.stream().anyMatch(f -> f.get("title").toString().contains("JavaScript"));
        assertThat(foundJs).isTrue();
    }

    @Test
    void analyze_apk_fileAccessWebView_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "setAllowFileAccess(true)");
        boolean foundFile = result.stream().anyMatch(f -> f.get("title").toString().contains("File Access"));
        assertThat(foundFile).isTrue();
    }

    @Test
    void analyze_apk_deepLinkWithoutVerify_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "intent-filter VIEW");
        boolean foundDeepLink = result.stream().anyMatch(f -> f.get("title").toString().contains("Deep Link"));
        assertThat(foundDeepLink).isTrue();
    }

    @Test
    void analyze_apk_hardcodedSecret_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "api_key=secret123");
        boolean foundSecret = result.stream().anyMatch(f -> f.get("title").toString().contains("Hardcoded"));
        assertThat(foundSecret).isTrue();
    }

    @Test
    void analyze_apk_externalStorage_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "getExternalFilesDir");
        boolean foundStorage = result.stream().anyMatch(f -> f.get("title").toString().contains("External Storage"));
        assertThat(foundStorage).isTrue();
    }

    @Test
    void analyze_apk_weakCrypto_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "AES/ECB");
        boolean foundCrypto = result.stream().anyMatch(f -> f.get("title").toString().contains("Weak Crypto"));
        assertThat(foundCrypto).isTrue();
    }

    @Test
    void analyze_apk_noRootDetection_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", null);
        boolean foundRoot = result.stream().anyMatch(f -> f.get("title").toString().contains("Root Detection"));
        assertThat(foundRoot).isTrue();
    }

    @Test
    void analyze_apk_logcatLogging_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", "Log.d(TAG, msg)");
        boolean foundLog = result.stream().anyMatch(f -> f.get("title").toString().contains("Logging"));
        assertThat(foundLog).isTrue();
    }

    @Test
    void analyze_ipa_atsDisabled_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", "NSAppTransportSecurity NSAllowsArbitraryLoads=YES");
        boolean foundAts = result.stream().anyMatch(f -> f.get("title").toString().contains("ATS"));
        assertThat(foundAts).isTrue();
    }

    @Test
    void analyze_ipa_fileSharing_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", "UIFileSharingEnabled=YES");
        boolean foundSharing = result.stream().anyMatch(f -> f.get("title").toString().contains("File Sharing"));
        assertThat(foundSharing).isTrue();
    }

    @Test
    void analyze_ipa_noKeychain_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.ipa", null);
        boolean foundKeychain = result.stream().anyMatch(f -> f.get("title").toString().contains("Keychain"));
        assertThat(foundKeychain).isTrue();
    }

    @Test
    void analyze_aab_detected() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.aab", null);
        assertThat(result).isNotEmpty();
        boolean foundAab = result.stream().anyMatch(f -> f.get("title").toString().contains("AAB"));
        assertThat(foundAab).isTrue();
    }

    @Test
    void analyze_unknownFile_notMobile() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("readme.md", null);
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("title").toString()).contains("Not a Mobile");
    }

    @Test
    void analyze_fields_complete() {
        List<Map<String, Object>> result = MobileAnalyzer.analyze("app.apk", null);
        assertThat(result).isNotEmpty();
        Map<String, Object> f = result.get(0);
        assertThat(f).containsKey("title");
        assertThat(f).containsKey("cwe");
        assertThat(f).containsKey("severity");
        assertThat(f).containsKey("recommendation");
    }
}
