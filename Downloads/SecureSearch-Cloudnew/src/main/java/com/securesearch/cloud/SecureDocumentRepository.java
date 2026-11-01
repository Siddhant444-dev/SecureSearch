package com.securesearch.cloud;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecureDocumentRepository extends JpaRepository<SecureDocument, String> {}
