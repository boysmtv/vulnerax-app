package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class PluginRegistry {

    private final Map<String, SecurityScannerPlugin> plugins = new LinkedHashMap<>();

    public PluginRegistry(List<SecurityScannerPlugin> pluginList) {
        for (SecurityScannerPlugin p : pluginList) {
            plugins.put(p.getId(), p);
        }
    }

    public SecurityScannerPlugin getPlugin(String id) {
        return plugins.get(id);
    }

    public List<SecurityScannerPlugin> getAllPlugins() {
        return List.copyOf(plugins.values());
    }

    public List<SecurityScannerPlugin> getPluginsForTarget(String targetType) {
        return plugins.values().stream()
                .filter(p -> p.getSupportedTargetTypes().contains(targetType))
                .toList();
    }

    public List<Map<String, Object>> scan(String targetType, String targetUrl, Map<String, String> options) {
        List<Map<String, Object>> allResults = new ArrayList<>();
        for (SecurityScannerPlugin plugin : getPluginsForTarget(targetType)) {
            try {
                SecurityScannerPlugin.ScanPlan plan = plugin.plan(targetUrl, options);
                List<Finding> findings = plugin.execute(targetUrl, plan, options);
                for (Finding f : findings) {
                    f = plugin.normalize(f, options);
                    SecurityScannerPlugin.ValidationResult v = plugin.validate(f);
                    if (v.valid()) {
                        allResults.add(Map.of("plugin", plugin.getId(), "finding", f));
                    }
                }
            } catch (Exception e) {
                allResults.add(Map.of("plugin", plugin.getId(), "error", e.getMessage()));
            }
        }
        return allResults;
    }
}
