package com.vulnerax.modules.search;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/search")
@RequiredArgsConstructor
public class SearchController {
    private final AssetRepository assetRepo;
    private final FindingRepository findingRepo;

    @GetMapping
    public ApiResponse<?> search(@RequestParam String q) {
        String lower = q.toLowerCase();
        var assets = assetRepo.findAll().stream()
                .filter(a-> a.getName().toLowerCase().contains(lower) || (a.getIdentifier()!=null && a.getIdentifier().toLowerCase().contains(lower)) || a.getType().toLowerCase().contains(lower))
                .limit(10).map(a-> Map.of("type","ASSET","id",a.getId(),"name",a.getName(),"assetType",a.getType())).toList();
        var findings = findingRepo.findAll().stream()
                .filter(f-> f.getTitle().toLowerCase().contains(lower) || (f.getCwe()!=null && f.getCwe().toLowerCase().contains(lower)) || (f.getFindingId()!=null && f.getFindingId().toLowerCase().contains(lower)))
                .limit(10).map(f-> Map.of("type","FINDING","id",f.getId(),"findingId",f.getFindingId(),"title",f.getTitle(),"severity",f.getSeverity())).toList();
        List<Object> combined = new ArrayList<>();
        combined.addAll(assets);
        combined.addAll(findings);
        return ApiResponse.ok(Map.of("query", q, "results", combined, "total", combined.size()));
    }
}
