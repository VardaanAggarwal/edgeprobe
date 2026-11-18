package dev.vardaan.edgeprobe.api.web;

import dev.vardaan.edgeprobe.api.scan.ScanService;
import dev.vardaan.edgeprobe.api.scan.ScanService.CacheStatus;
import dev.vardaan.edgeprobe.api.scan.ScanService.ScanResult;
import dev.vardaan.edgeprobe.api.scan.ScanViews.CheckView;
import dev.vardaan.edgeprobe.api.scan.ScanViews.PageView;
import dev.vardaan.edgeprobe.api.scan.ScanViews.ScanSummaryView;
import dev.vardaan.edgeprobe.api.scan.ScanViews.ScanView;
import dev.vardaan.edgeprobe.core.engine.ScanEngine;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Scans", description = "Scan web properties and read scan history")
public class ScanController {

    static final String CACHE_HEADER = "X-Edgeprobe-Cache";

    private final ScanService scans;
    private final ScanEngine engine;

    public ScanController(ScanService scans, ScanEngine engine) {
        this.scans = scans;
        this.engine = engine;
    }

    /** @param fresh optional; true skips the result cache. A Boolean, because Jackson 3 rejects a missing primitive. */
    public record ScanRequest(@NotBlank @Size(max = 2048) String url, Boolean fresh) {
        boolean skipCache() {
            return Boolean.TRUE.equals(fresh);
        }
    }

    @PostMapping("/scans")
    @Operation(summary = "Scan a URL",
            description = "Returns 201 for a new scan, or 200 with X-Edgeprobe-Cache: HIT or COALESCED when "
                    + "a recent or in-progress scan of the same URL was reused. Set fresh=true to skip the cache.")
    public ResponseEntity<ScanView> create(@Valid @RequestBody ScanRequest request) {
        ScanResult result = scans.scan(request.url(), request.skipCache());
        ScanView view = result.scan();
        HttpStatus status = result.cacheStatus() == CacheStatus.MISS ? HttpStatus.CREATED : HttpStatus.OK;
        return ResponseEntity.status(status)
                .location(URI.create("/api/v1/scans/" + view.id()))
                .header(CACHE_HEADER, result.cacheStatus().name())
                .body(view);
    }

    @GetMapping("/scans/{id}")
    @Operation(summary = "Get one scan with all findings")
    public ScanView get(@PathVariable UUID id) {
        return scans.get(id);
    }

    @GetMapping("/scans")
    @Operation(summary = "List scans, newest first, optionally for one host")
    public PageView<ScanSummaryView> history(@RequestParam(required = false) String host,
                                             @RequestParam(defaultValue = "0") @Min(0) int page,
                                             @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return scans.history(host, page, size);
    }

    @GetMapping("/checks")
    @Operation(summary = "List the checks every scan runs")
    public List<CheckView> checks() {
        return engine.checks().stream().map(c -> new CheckView(c.id(), c.description())).toList();
    }
}
