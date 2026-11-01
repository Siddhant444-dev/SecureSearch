package com.securesearch.cloud;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "secure_documents")
public class SecureDocument {
    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 4096)
    private String encryptedName;

    @Column(nullable = false, length = 64)
    private String nameIv;

    @Column(nullable = false, length = 64)
    private String contentIv;

    @Column(nullable = false, length = 32)
    private String mediaType;

    @Column(nullable = false)
    private long sizeBytes;

    @Column(nullable = false, length = 16777216)
    private String encryptedContent;

    @Column(nullable = false)
    private Instant uploadedAt;

    protected SecureDocument() {}

    public SecureDocument(String id, String encryptedName, String nameIv, String contentIv,
                          String mediaType, long sizeBytes, String encryptedContent, Instant uploadedAt) {
        this.id = id;
        this.encryptedName = encryptedName;
        this.nameIv = nameIv;
        this.contentIv = contentIv;
        this.mediaType = mediaType;
        this.sizeBytes = sizeBytes;
        this.encryptedContent = encryptedContent;
        this.uploadedAt = uploadedAt;
    }

    public String getId() { return id; }
    public String getEncryptedName() { return encryptedName; }
    public String getNameIv() { return nameIv; }
    public String getContentIv() { return contentIv; }
    public String getMediaType() { return mediaType; }
    public long getSizeBytes() { return sizeBytes; }
    public String getEncryptedContent() { return encryptedContent; }
    public Instant getUploadedAt() { return uploadedAt; }
}
