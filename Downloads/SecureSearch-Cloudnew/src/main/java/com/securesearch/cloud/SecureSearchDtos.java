package com.securesearch.cloud;

import java.time.Instant;
import java.util.List;

public final class SecureSearchDtos {
    private SecureSearchDtos() {}

    public record UploadRequest(String encryptedName, String nameIv, String contentIv,
                                String encryptedContent, String mediaType, long sizeBytes,
                                List<String> keywordTokens) {}
    public record SearchRequest(List<String> tokens) {}
    public record DocumentSummary(String id, String encryptedName, String nameIv,
                                  String mediaType, long sizeBytes, Instant uploadedAt) {}
    public record SearchResponse(List<DocumentSummary> results, int queryTokenCount,
                                 long elapsedMillis, String matching) {}
    public record EncryptedDocument(String id, String encryptedName, String nameIv,
                                    String contentIv, String encryptedContent, String mediaType,
                                    long sizeBytes, Instant uploadedAt) {}
    public record UploadResponse(String id, int indexedTokenCount, Instant uploadedAt) {}
}
