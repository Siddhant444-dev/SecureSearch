package com.securesearch.cloud;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface KeywordIndexRepository extends JpaRepository<KeywordIndexEntry, String> {
    List<KeywordIndexEntry> findByTokenIn(Collection<String> tokens);

    @Modifying
    @Query("delete from KeywordIndexEntry e where e.documentId = :documentId")
    void deleteForDocument(@Param("documentId") String documentId);
}
