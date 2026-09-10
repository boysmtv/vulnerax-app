package com.vulnerax.modules.reporting;

import com.vulnerax.modules.ai.AiAnalystService;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ReportService {
    private final ReportRepository repo;
    private final FindingRepository findingRepo;
    private final AssetRepository assetRepo;
    private final AiAnalystService aiService;

    @Transactional
    public Report generate(UUID projectId, String type, String title, String format) {
        Map<String,Object> draft = aiService.reportDraft(projectId, type);
        long totalFindings = findingRepo.findByProjectId(projectId).size();
        long totalAssets = assetRepo.findByProjectId(projectId).size();
        Map<String,Object> content = new HashMap<>();
        content.put("draft", draft);
        content.put("projectId", projectId);
        content.put("generatedAt", new Date());
        content.put("stats", Map.of("findings", totalFindings, "assets", totalAssets));
        content.put("type", type);
        // simple JSON string
        String json;
        try { json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(content); } catch (Exception e) { json = "{}"; }
        Report r = Report.builder()
                .projectId(projectId)
                .type(type!=null?type:"EXECUTIVE")
                .title(title!=null?title: type + " Report - " + projectId)
                .format(format!=null?format:"PDF")
                .status("READY")
                .contentJson(json)
                .generatedBy("system")
                .classification("CONFIDENTIAL")
                .filePath("s3://vulnerax-reports/" + projectId + "/" + UUID.randomUUID() + "." + (format!=null?format.toLowerCase():"pdf"))
                .build();
        return repo.save(r);
    }

    public List<Report> list(UUID projectId) {
        if (projectId!=null) return repo.findByProjectId(projectId);
        return repo.findAll();
    }

    public Report get(UUID id) { return repo.findById(id).orElseThrow(() -> new RuntimeException("Report not found")); }

    public Map<String,Object> export(UUID id, String format) {
        Report r = get(id);
        // mock export: returns content json with format
        return Map.of("id", r.getId(), "title", r.getTitle(), "format", format!=null?format:r.getFormat(), "content", r.getContentJson(), "downloadUrl", r.getFilePath());
    }
}
