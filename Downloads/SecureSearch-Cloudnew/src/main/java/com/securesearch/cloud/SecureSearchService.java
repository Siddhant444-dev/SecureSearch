package com.securesearch.cloud;

import static com.securesearch.cloud.SecureSearchDtos.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class SecureSearchService {
    private static final Pattern TOKEN = Pattern.compile("[0-9a-fA-F]{64}");
    private static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    private final SecureDocumentRepository documents;
    private final KeywordIndexRepository index;

    public SecureSearchService(SecureDocumentRepository documents, KeywordIndexRepository index) {
        this.documents = documents;
        this.index = index;
    }

    @Transactional
    public UploadResponse upload(UploadRequest request) {
        if (request == null) throw badRequest("A document payload is required.");
        validateCipher(request.encryptedName(), "encryptedName", 4096);
        validateIv(request.nameIv(), "nameIv");
        validateIv(request.contentIv(), "contentIv");
        validateCipher(request.encryptedContent(), "encryptedContent", 15_000_000);
        if (request.sizeBytes() < 1 || request.sizeBytes() > MAX_FILE_BYTES) {
            throw badRequest("PDFs must be between 1 byte and 10 MiB.");
        }
        if (!"application/pdf".equalsIgnoreCase(request.mediaType())) {
            throw badRequest("Only PDF documents are accepted.");
        }
        if (request.keywordTokens() == null || request.keywordTokens().isEmpty() || request.keywordTokens().size() > 10_000) {
            throw badRequest("A document must contain between 1 and 10,000 indexed terms.");
        }
        Set<String> tokens = new LinkedHashSet<>();
        for (String token : request.keywordTokens()) {
            if (token == null || !TOKEN.matcher(token).matches()) throw badRequest("Search tokens must be 32-byte HMAC-SHA-256 hex values.");
            tokens.add(token.toLowerCase(Locale.ROOT));
        }
        if (tokens.isEmpty()) throw badRequest("At least one unique keyword is required.");

        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        SecureDocument document = new SecureDocument(id, request.encryptedName(), request.nameIv(),
                request.contentIv(), "application/pdf", request.sizeBytes(), request.encryptedContent(), now);
        documents.save(document);
        List<KeywordIndexEntry> entries = new ArrayList<>(tokens.size());
        for (String token : tokens) entries.add(new KeywordIndexEntry(token, id));
        index.saveAll(entries);
        return new UploadResponse(id, entries.size(), now);
    }

    @Transactional(readOnly = true)
    public List<DocumentSummary> list() {
        return documents.findAll().stream()
                .sorted((a, b) -> b.getUploadedAt().compareTo(a.getUploadedAt()))
                .map(this::summary)
                .toList();
    }

    @Transactional(readOnly = true)
    public SearchResponse search(SearchRequest request) {
        long started = System.nanoTime();
        if (request == null || request.tokens() == null || request.tokens().isEmpty() || request.tokens().size() > 20) {
            throw badRequest("Search with between 1 and 20 keywords.");
        }
        Set<String> tokens = new LinkedHashSet<>();
        for (String token : request.tokens()) {
            if (token == null || !TOKEN.matcher(token).matches()) throw badRequest("Search tokens must be 32-byte HMAC-SHA-256 hex values.");
            tokens.add(token.toLowerCase(Locale.ROOT));
        }
        List<KeywordIndexEntry> hits = index.findByTokenIn(tokens);
        Map<String, Integer> matchCounts = new HashMap<>();
        for (KeywordIndexEntry hit : hits) matchCounts.merge(hit.getDocumentId(), 1, Integer::sum);
        List<String> matchingIds = matchCounts.entrySet().stream()
                .filter(entry -> entry.getValue() == tokens.size())
                .map(Map.Entry::getKey)
                .toList();
        List<DocumentSummary> results = documents.findAllById(matchingIds).stream()
                .sorted((a, b) -> b.getUploadedAt().compareTo(a.getUploadedAt()))
                .map(this::summary)
                .toList();
        long elapsed = (System.nanoTime() - started) / 1_000_000;
        return new SearchResponse(results, tokens.size(), elapsed, "AND");
    }

    @Transactional(readOnly = true)
    public EncryptedDocument get(String id) {
        SecureDocument d = documents.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found."));
        return new EncryptedDocument(d.getId(), d.getEncryptedName(), d.getNameIv(), d.getContentIv(),
                d.getEncryptedContent(), d.getMediaType(), d.getSizeBytes(), d.getUploadedAt());
    }

    @Transactional
    public void delete(String id) {
        if (!documents.existsById(id)) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found.");
        index.deleteForDocument(id);
        documents.deleteById(id);
    }

    private DocumentSummary summary(SecureDocument d) {
        return new DocumentSummary(d.getId(), d.getEncryptedName(), d.getNameIv(), d.getMediaType(), d.getSizeBytes(), d.getUploadedAt());
    }

    private void validateIv(String value, String field) {
        validateCipher(value, field, 64);
        final byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw badRequest(field + " must be valid base64.");
        }
        if (decoded.length != 12) throw badRequest(field + " must be a 96-bit AES-GCM nonce.");
    }

    private void validateCipher(String value, String field, int maxChars) {
        if (value == null || value.isBlank() || value.length() > maxChars) throw badRequest(field + " is missing or too large.");
        try { Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException e) { throw badRequest(field + " must be valid base64."); }
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
