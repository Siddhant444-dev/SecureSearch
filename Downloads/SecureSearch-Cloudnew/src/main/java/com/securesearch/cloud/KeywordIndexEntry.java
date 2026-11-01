package com.securesearch.cloud;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.UUID;

@Entity
@Table(name = "secure_keyword_index",
       indexes = @Index(name = "idx_secure_keyword_token", columnList = "token"),
       uniqueConstraints = @UniqueConstraint(name = "uk_secure_token_document", columnNames = {"token", "document_id"}))
public class KeywordIndexEntry {
    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 64)
    private String token;

    @Column(name = "document_id", nullable = false, length = 36)
    private String documentId;

    protected KeywordIndexEntry() {}

    public KeywordIndexEntry(String token, String documentId) {
        this.id = UUID.randomUUID().toString();
        this.token = token;
        this.documentId = documentId;
    }

    public String getToken() { return token; }
    public String getDocumentId() { return documentId; }
}
