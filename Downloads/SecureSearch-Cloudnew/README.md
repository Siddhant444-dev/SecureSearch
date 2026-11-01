# SecureSearch Cloud

A standalone, educational Spring Boot project for **searching client-encrypted PDFs in cloud storage**. The browser encrypts each file and filename before upload, creates deterministic HMAC-SHA-256 keyword tokens locally, and submits only those opaque tokens for server-side index lookup.

This repository/project has **no dependency on the BankingApplication**. It has its own Maven build, Java package, Spring Boot entry point, configuration, tests, Docker setup, and browser UI.

> **Research prototype—not production-ready.** The SecureSearch API is unauthenticated and single-user by design for local demonstrations. Do not expose it publicly or upload sensitive real documents. The searchable-encryption design reveals repeated-query and matching-document patterns.

## What it includes

- Browser-side **AES-256-GCM** encryption for PDF content and filenames, with independent random 96-bit nonces.
- Passphrase-based key derivation using **PBKDF2-HMAC-SHA-256**, 310,000 iterations, and a random 128-bit workspace salt; the resulting 512 bits are split into separate 256-bit AES and HMAC keys.
- Automatic browser-side text extraction from selectable PDF text; fixed-length HMAC blind-index tokens; exact lookup with **AND semantics** across search terms.
- Bundled PDF.js 6.4.299 parses PDFs locally; the original PDF and extracted text are not sent to a PDF-processing service.
- Browser-side filename and PDF decryption on retrieval.
- Spring Boot REST API and JPA persistence.
- H2 local development database and PostgreSQL 16 Docker Compose deployment option.
- Responsive browser dashboard and a synthetic in-memory benchmarking endpoint for 1k, 10k, and 50k document scales.
- Maven Wrapper and integration tests.

## Stack

- Java 21 · Spring Boot 3.5 · Spring Web · Spring Data JPA
- H2 (local) · PostgreSQL 16 (Docker Compose)
- Browser Web Crypto API · vanilla JavaScript (no frontend build step)

The browser uses PDF.js [`getDocument()` and `getTextContent()`](https://mozilla.github.io/pdf.js/examples/) to extract a local text layer. The vendored PDF.js 6.4.299 runtime is licensed under Apache-2.0; its license and the related CMap, font, and WASM notices are included under `src/main/resources/static/assets/vendor/pdfjs/`.

## Run locally

### Prerequisites

- JDK 21 (a JRE alone is not sufficient)
- Internet access for the first build so Maven dependencies can be downloaded

```bash
chmod +x mvnw
./mvnw test
./mvnw spring-boot:run
```

Open [http://localhost:8080](http://localhost:8080). H2 stores the local database under `./data/securesearch`.

On first use, choose a strong passphrase of at least 12 characters. The random salt and a passphrase verifier are kept in this browser's local storage. The passphrase and derived keys are not sent to the server. **Use the same browser profile and do not clear site storage:** there is no salt backup, password recovery, or multi-device key sync yet. If local storage or the salt is lost, files encrypted under that workspace cannot be decrypted.

### Run with PostgreSQL and Docker Compose

Override the sample database password before starting:

```bash
export POSTGRES_PASSWORD='replace-with-a-long-random-password'
docker compose up --build
```

The dashboard is available at `http://localhost:8080`. Database data is kept in the `securesearch-db` volume. For non-local use, place the service behind HTTPS/TLS, but **do not publish this unauthenticated prototype** without first adding tenant-scoped access control and abuse protections.

### Environment settings

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `jdbc:h2:file:./data/securesearch;DB_CLOSE_ON_EXIT=FALSE` | JDBC connection URL |
| `DATABASE_USERNAME` | `sa` | Database username |
| `DATABASE_PASSWORD` | empty | Database password |
| `DATABASE_DRIVER` | `org.h2.Driver` | JDBC driver (`org.postgresql.Driver` for PostgreSQL) |
| `H2_CONSOLE_ENABLED` | `false` | Optional local H2 console toggle |

## Try the demo

1. Unlock the workspace with a strong passphrase.
2. Choose a PDF no larger than 10 MiB. The browser checks the `.pdf` extension, MIME type when provided, and `%PDF-` signature.
3. Upload. The browser extracts selectable text locally, derives keyword tokens, and encrypts the PDF/name before sending ciphertext and opaque tokens to the server. You do not enter upload keywords.
4. Type one or more words from the PDF into Search. Search terms are normalized and HMACed in the browser; all query terms must match.
5. Download a result. The browser retrieves ciphertext and decrypts it locally.
6. Run the benchmark and review the privacy dialog for leakage and limitations.

PDF text extraction runs entirely in the browser using the bundled PDF.js parser. The prototype indexes up to 10,000 distinct terms from PDFs with selectable text and limits extraction to 1,000 pages. Scanned/image-only PDFs have no text layer, so they require OCR; OCR is not included. Password-protected PDFs must be unlocked before uploading.

## REST API

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/secure-search/documents` | Save encrypted content/name plus HMAC keyword tokens |
| `GET` | `/api/secure-search/documents` | List encrypted document summaries |
| `POST` | `/api/secure-search/search` | Find document IDs using blind tokens (AND matching) |
| `GET` | `/api/secure-search/documents/{id}` | Retrieve encrypted content for client-side decryption |
| `DELETE` | `/api/secure-search/documents/{id}` | Delete a document and its token index entries |
| `POST` | `/api/benchmarks/run` | Run the synthetic benchmark at three dataset scales |

Illustrative encrypted upload payload:

```json
{
  "encryptedName": "BASE64_AES_GCM_CIPHERTEXT",
  "nameIv": "BASE64_12_BYTE_NONCE",
  "contentIv": "BASE64_12_BYTE_NONCE",
  "encryptedContent": "BASE64_AES_GCM_CIPHERTEXT",
  "mediaType": "application/pdf",
  "sizeBytes": 12345,
  "keywordTokens": ["64_HEX_CHAR_HMAC_SHA256_TOKEN"]
}
```

Search accepts only precomputed tokens; there is no plaintext query field:

```json
{ "tokens": ["64_HEX_CHAR_HMAC_SHA256_TOKEN"] }
```

## Benchmark design and interpretation

The benchmark builds synthetic plaintext and HMAC-keyed `HashMap` indexes at 1,000, 10,000, and 50,000 synthetic documents. It prepares tokens before timing so each strategy measures the equivalent lookup operation. Storage output is a rough key/value byte estimate, not actual database size.

It is **not** a production claim. The benchmark excludes database/network I/O, concurrency, client-side PDF parsing, complete browser timing, index construction, and application deployment overhead. Run repeated trials in a controlled environment and report the scope and leakage assumptions with any results.

## Security model and limitations

### Protected from the storage/search API

- PDF bytes and filenames: AES-256-GCM ciphertext generated in the browser.
- Plaintext search words and the HMAC key: the browser sends only fixed-length HMAC tokens.
- Nonce reuse: each name and content encryption receives its own fresh random nonce.

### Leakage and missing production controls

- **Query equality/frequency:** deterministic HMAC tokens reveal repeated searches for the same word; frequency analysis may help guess popular keywords.
- **Access patterns:** the server observes which encrypted document IDs match, result counts, timing, and request cadence.
- **Metadata:** approximate file size and timestamps remain visible; the prototype does not pad ciphertext or hide traffic patterns.
- **No authentication or tenancy:** anyone with network access can list, upload, search, and delete records. Client-side encryption does not prevent deletion, denial-of-service, or metadata observation. Keep the app local.
- **Single-browser key lifecycle:** local storage holds the salt/verifier. Recovery, rotation, cross-device access, and account isolation are not implemented.
- **Text layer only:** selectable text is indexed automatically in the browser. Scanned/image-only PDFs require OCR, which is not implemented; PDFs above the page or token cap are not fully indexed. Language-specific tokenization and a stop-word policy are also future work.
- **No formal security claim:** this is a simple client-side SSE-style demonstration, not a reviewed or formally proven searchable symmetric encryption construction. It does not claim forward privacy, ORAM, or formal leakage simulation.

A production system would need a reviewed SSE construction, authenticated tenant-scoped APIs, TLS, key recovery/rotation, rate limits and abuse defenses, database/network benchmarking, and independent security review.

## Tests

```bash
./mvnw test
```

Integration tests cover encrypted payload upload, HMAC-token AND search, retrieval, deletion, malformed-token rejection, and benchmark result shape. Tests use an isolated in-memory H2 database.

## Project layout

```text
src/main/java/com/securesearch/cloud/   Standalone Spring Boot app, API, persistence and benchmark
src/main/resources/static/              Dashboard and browser cryptography client
src/main/resources/application.properties
src/test/java/com/securesearch/cloud/   API integration tests
compose.yaml                            PostgreSQL + application
```
