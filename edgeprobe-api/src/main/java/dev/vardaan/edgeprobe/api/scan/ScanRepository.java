package dev.vardaan.edgeprobe.api.scan;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanRepository extends JpaRepository<ScanEntity, UUID> {

    /** Loads a scan and its findings in one query instead of N+1. */
    @EntityGraph(attributePaths = "findings")
    Optional<ScanEntity> findWithFindingsById(UUID id);

    /** History for one host, newest first. Served by the (host, started_at DESC) index. */
    Page<ScanEntity> findByHostOrderByStartedAtDesc(String host, Pageable pageable);

    Page<ScanEntity> findAllByOrderByStartedAtDesc(Pageable pageable);
}
