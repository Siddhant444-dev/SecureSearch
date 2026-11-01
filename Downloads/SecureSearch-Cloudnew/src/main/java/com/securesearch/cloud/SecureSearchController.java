package com.securesearch.cloud;

import static com.securesearch.cloud.SecureSearchDtos.*;

import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secure-search")
public class SecureSearchController {
    private final SecureSearchService service;

    public SecureSearchController(SecureSearchService service) { this.service = service; }

    @PostMapping("/documents")
    @ResponseStatus(HttpStatus.CREATED)
    public UploadResponse upload(@RequestBody UploadRequest request) { return service.upload(request); }

    @GetMapping("/documents")
    public List<DocumentSummary> list() { return service.list(); }

    @PostMapping("/search")
    public SearchResponse search(@RequestBody SearchRequest request) { return service.search(request); }

    @GetMapping("/documents/{id}")
    public EncryptedDocument get(@PathVariable String id) { return service.get(id); }

    @DeleteMapping("/documents/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String id) { service.delete(id); }
}
