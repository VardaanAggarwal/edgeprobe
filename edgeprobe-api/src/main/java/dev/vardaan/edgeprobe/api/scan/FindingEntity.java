package dev.vardaan.edgeprobe.api.scan;

import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "finding")
public class FindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id")
    private ScanEntity scan;

    @Column(nullable = false)
    private int position;

    @Column(name = "check_id", nullable = false, length = 64)
    private String checkId;

    @Column(nullable = false, length = 128)
    private String code;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 8)
    private Outcome outcome;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 8)
    private Severity severity;

    @Column(nullable = false, length = 500)
    private String title;

    @Column(nullable = false, columnDefinition = "text")
    private String detail;

    @Column(nullable = false, columnDefinition = "text")
    private String remediation;

    protected FindingEntity() {
    }

    public FindingEntity(String checkId, String code, Outcome outcome, Severity severity, String title,
                         String detail, String remediation) {
        this.checkId = checkId;
        this.code = code;
        this.outcome = outcome;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.remediation = remediation;
    }

    void attachTo(ScanEntity owner, int index) {
        this.scan = owner;
        this.position = index;
    }

    public String getCheckId() {
        return checkId;
    }

    public String getCode() {
        return code;
    }

    public Outcome getOutcome() {
        return outcome;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }

    public String getRemediation() {
        return remediation;
    }
}
