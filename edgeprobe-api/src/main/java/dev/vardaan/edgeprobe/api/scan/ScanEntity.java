package dev.vardaan.edgeprobe.api.scan;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "scan")
public class ScanEntity {

    @Id
    private UUID id;

    @Column(nullable = false, length = 2100)
    private String url;

    @Column(nullable = false)
    private String host;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "duration_ms", nullable = false)
    private long durationMs;

    @Column(nullable = false)
    private int score;

    @Column(nullable = false, length = 2)
    private String grade;

    @Column(name = "fail_count", nullable = false)
    private int failCount;

    @Column(name = "warn_count", nullable = false)
    private int warnCount;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("position")
    private List<FindingEntity> findings = new ArrayList<>();

    protected ScanEntity() {
    }

    public ScanEntity(UUID id, String url, String host, Instant startedAt, long durationMs, int score,
                      String grade, int failCount, int warnCount) {
        this.id = id;
        this.url = url;
        this.host = host;
        this.startedAt = startedAt;
        this.durationMs = durationMs;
        this.score = score;
        this.grade = grade;
        this.failCount = failCount;
        this.warnCount = warnCount;
    }

    public void addFinding(FindingEntity finding) {
        finding.attachTo(this, findings.size());
        findings.add(finding);
    }

    public UUID getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public String getHost() {
        return host;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public int getScore() {
        return score;
    }

    public String getGrade() {
        return grade;
    }

    public int getFailCount() {
        return failCount;
    }

    public int getWarnCount() {
        return warnCount;
    }

    public List<FindingEntity> getFindings() {
        return findings;
    }
}
