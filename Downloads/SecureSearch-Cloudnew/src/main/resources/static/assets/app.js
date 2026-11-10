import * as pdfjsLib from './vendor/pdfjs/pdf.min.mjs';

pdfjsLib.GlobalWorkerOptions.workerSrc = '/assets/vendor/pdfjs/pdf.worker.min.mjs';

(() => {
  const API = '/api/secure-search';
  const SALT_KEY = 'securesearch.workspaceSalt.v1';
  const VERIFY_KEY = 'securesearch.keyVerifier.v1';
  const ITERATIONS = 310000;
  const MAX_INDEX_TERMS = 10000;
  const MAX_PDF_PAGES = 1000;
  const $ = (id) => document.getElementById(id);
  let aesKey = null;
  let hmacKey = null;
  let isUnlocked = false;

  const randomBytes = (size) => crypto.getRandomValues(new Uint8Array(size));
  const b64 = (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  };
  const fromB64 = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const textToBytes = (value) => new TextEncoder().encode(value);
  const bytesToText = (value) => new TextDecoder().decode(value);

  async function deriveKeys(passphrase, salt) {
    const material = await crypto.subtle.importKey('raw', textToBytes(passphrase), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, 512));
    const aes = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const hmac = await crypto.subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    bits.fill(0);
    return { aes, hmac };
  }

  async function encryptBytes(bytes, key) {
    const iv = randomBytes(12);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { cipher: b64(new Uint8Array(encrypted)), iv: b64(iv) };
  }
  async function decryptBytes(cipher, iv, key) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv) }, key, fromB64(cipher)));
  }
  async function tokenFor(word) {
    return hex(new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, textToBytes(word))));
  }
  function words(value) {
    return [...new Set(value.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]{2,}/gu) || [])];
  }
  async function tokensFor(terms) {
    const tokens = [];
    for (let start = 0; start < terms.length; start += 128) {
      tokens.push(...await Promise.all(terms.slice(start, start + 128).map(tokenFor)));
    }
    return tokens;
  }
  async function extractPdfTerms(file, onProgress) {
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    let loadingTask;
    let pdf;
    try {
      loadingTask = pdfjsLib.getDocument({
        data: fileBytes.slice(),
        cMapUrl: '/assets/vendor/pdfjs/cmaps/',
        cMapPacked: true,
        standardFontDataUrl: '/assets/vendor/pdfjs/standard_fonts/',
        wasmUrl: '/assets/vendor/pdfjs/wasm/',
        isEvalSupported: false
      });
      pdf = await loadingTask.promise;
      if (pdf.numPages > MAX_PDF_PAGES) throw new Error(`This prototype indexes PDFs up to ${MAX_PDF_PAGES.toLocaleString()} pages.`);
      const terms = new Set();
      for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber++) {
        const page = await pdf.getPage(pageNumber);
        const text = await page.getTextContent();
        for (const item of text.items) {
          if (typeof item.str !== 'string') continue;
          for (const term of words(item.str)) {
            terms.add(term);
            if (terms.size >= MAX_INDEX_TERMS) break;
          }
          if (terms.size >= MAX_INDEX_TERMS) break;
        }
        page.cleanup();
        onProgress(pageNumber, pdf.numPages, terms.size);
        if (terms.size >= MAX_INDEX_TERMS) break;
      }
      if (!terms.size) throw new Error('No searchable text was found. This may be a scanned/image-only PDF; OCR is not included.');
      return { terms: [...terms], fileBytes, truncated: terms.size >= MAX_INDEX_TERMS };
    } catch (error) {
      fileBytes.fill(0);
      if (error?.name === 'PasswordException') throw new Error('This PDF is password-protected. Unlock it before uploading.');
      throw error;
    } finally {
      if (loadingTask) await loadingTask.destroy();
    }
  }
  function bytesLabel(bytes) {
    return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
  function dateLabel(date) {
    return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(date));
  }
  function fileStem(name) { return name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 160) || 'secure-document.pdf'; }

  async function api(url, options = {}) {
    const response = await fetch(url, { ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers } });
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try { const body = await response.json(); message = body.detail || body.message || message; } catch (_) { /* no json response */ }
      throw new Error(message);
    }
    return response.status === 204 ? null : response.json();
  }

  async function displayDocuments(documents, searched = false) {
    $('nav-count').textContent = String(documents.length);
    $('stat-documents').textContent = String(documents.length);
    $('result-count').textContent = String(documents.length);
    const list = $('document-list');
    list.replaceChildren();
    if (!documents.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = `<div class="empty-illustration">⌕</div><strong>${searched ? 'No matching documents' : 'Your vault is empty'}</strong><p>${searched ? 'Try fewer or different words from your PDFs.' : 'Upload a PDF; searchable text is indexed automatically.'}</p>`;
      list.append(empty);
      return;
    }
    for (const doc of documents) {
      let filename = 'Encrypted document';
      try { filename = bytesToText(await decryptBytes(doc.encryptedName, doc.nameIv, aesKey)); }
      catch (_) { filename = 'Unable to decrypt name'; }
      const row = document.createElement('article');
      row.className = 'doc-row';
      const icon = document.createElement('div'); icon.className = 'doc-icon'; icon.textContent = 'PDF';
      const info = document.createElement('div'); info.className = 'doc-info';
      const title = document.createElement('strong'); title.textContent = filename;
      const detail = document.createElement('span'); detail.textContent = `${bytesLabel(doc.sizeBytes)} · added ${dateLabel(doc.uploadedAt)}`;
      info.append(title, detail);
      const actions = document.createElement('div'); actions.className = 'doc-actions';
      const download = document.createElement('button'); download.className = 'mini-button'; download.title = 'Decrypt and download PDF'; download.setAttribute('aria-label', `Download ${filename}`); download.textContent = '↓';
      download.addEventListener('click', () => downloadDocument(doc.id, filename, download));
      const remove = document.createElement('button'); remove.className = 'mini-button'; remove.title = 'Delete document'; remove.setAttribute('aria-label', `Delete ${filename}`); remove.textContent = '×';
      remove.addEventListener('click', () => deleteDocument(doc.id, remove));
      actions.append(download, remove); row.append(icon, info, actions); list.append(row);
    }
  }

  async function refresh() {
    if (!isUnlocked) return;
    const docs = await api(`${API}/documents`);
    $('results-description').textContent = 'Latest documents';
    $('search-time').textContent = '';
    await displayDocuments(docs, false);
  }

  async function downloadDocument(id, filename, button) {
    button.disabled = true;
    try {
      const payload = await api(`${API}/documents/${encodeURIComponent(id)}`);
      const bytes = await decryptBytes(payload.encryptedContent, payload.contentIv, aesKey);
      const blob = new Blob([bytes], { type: payload.mediaType || 'application/pdf' });
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a'); anchor.href = href; anchor.download = fileStem(filename); anchor.click();
      setTimeout(() => URL.revokeObjectURL(href), 30000);
    } catch (error) { alert(`Could not decrypt or download this document: ${error.message}`); }
    finally { button.disabled = false; }
  }

  async function deleteDocument(id, button) {
    if (!isUnlocked) return;
    button.disabled = true;
    try {
      await api(`${API}/documents/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await refresh();
    } catch (error) { alert(error.message); button.disabled = false; }
  }

  $('unlock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = $('unlock-error'); error.textContent = '';
    const passphrase = $('passphrase').value;
    if (passphrase.length < 12) { error.textContent = 'Use at least 12 characters for your passphrase.'; return; }
    const submit = event.currentTarget.querySelector('button'); submit.disabled = true; submit.textContent = 'Deriving keys…';
    try {
      if (!window.crypto?.subtle) throw new Error('Browser cryptography is unavailable. Use a modern browser over HTTPS or localhost.');
      let salt = localStorage.getItem(SALT_KEY);
      if (!salt) { salt = b64(randomBytes(16)); localStorage.setItem(SALT_KEY, salt); }
      const keys = await deriveKeys(passphrase, fromB64(salt));
      const check = hex(new Uint8Array(await crypto.subtle.sign('HMAC', keys.hmac, textToBytes('SecureSearch workspace key check v1'))));
      const savedCheck = localStorage.getItem(VERIFY_KEY);
      if (savedCheck && savedCheck !== check) throw new Error('That passphrase does not unlock this browser workspace.');
      if (!savedCheck) localStorage.setItem(VERIFY_KEY, check);
      aesKey = keys.aes; hmacKey = keys.hmac; isUnlocked = true;
      $('unlock-card').classList.add('unlocked');
      $('passphrase').value = '';
      $('upload-submit').disabled = false;
      $('search-form').querySelector('button').disabled = false;
      await refresh();
      error.textContent = '';
    } catch (err) { error.textContent = err.message; }
    finally { submit.disabled = false; submit.innerHTML = 'Unlock workspace <span>→</span>'; }
  });

  $('lock-button').addEventListener('click', () => {
    aesKey = null; hmacKey = null; isUnlocked = false;
    $('unlock-card').classList.remove('unlocked');
    $('upload-submit').disabled = true;
    $('search-form').querySelector('button').disabled = true;
    $('stat-documents').textContent = '—'; $('result-count').textContent = '0'; $('nav-count').textContent = '0';
    $('document-list').innerHTML = '<div class="empty-state"><div class="empty-illustration">▤</div><strong>Workspace locked</strong><p>Enter your passphrase to view encrypted filenames.</p></div>';
  });

  $('reset-workspace').addEventListener('click', () => {
    if (confirm('Reset workspace? This will clear all local encryption keys. Any documents encrypted with the previous passphrase will become unrecoverable.')) {
      localStorage.removeItem(SALT_KEY);
      localStorage.removeItem(VERIFY_KEY);
      aesKey = null; hmacKey = null; isUnlocked = false;
      $('unlock-card').classList.remove('unlocked');
      $('upload-submit').disabled = true;
      $('search-form').querySelector('button').disabled = true;
      $('stat-documents').textContent = '—'; $('result-count').textContent = '0'; $('nav-count').textContent = '0';
      $('document-list').innerHTML = '<div class="empty-state"><div class="empty-illustration">▤</div><strong>Workspace reset</strong><p>Enter a new passphrase to create a fresh workspace.</p></div>';
      $('unlock-error').textContent = '';
      $('passphrase').value = '';
    }
  });

  $('pdf-file').addEventListener('change', () => {
    const file = $('pdf-file').files[0];
    $('file-name').style.display = file ? 'block' : 'none';
    $('file-name').textContent = file ? `${file.name} · ${bytesLabel(file.size)}` : '';
  });
  const drop = $('drop-zone');
  for (const type of ['dragenter', 'dragover']) drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add('dragover'); });
  for (const type of ['dragleave', 'drop']) drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.remove('dragover'); });
  drop.addEventListener('drop', (e) => { const file = e.dataTransfer.files[0]; if (file) { $('pdf-file').files = e.dataTransfer.files; $('pdf-file').dispatchEvent(new Event('change')); } });

  $('upload-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const status = $('upload-status');
    if (!isUnlocked) { status.textContent = 'Unlock the workspace first.'; status.className = 'form-status error'; return; }
    const file = $('pdf-file').files[0];
    if (!file) { status.textContent = 'Choose a PDF first.'; status.className = 'form-status error'; return; }
    if (!file.name.toLowerCase().endsWith('.pdf') || (file.type && file.type !== 'application/pdf')) { status.textContent = 'Only PDF files are accepted.'; status.className = 'form-status error'; return; }
    if (!file.size || file.size > 10 * 1024 * 1024) { status.textContent = 'PDFs must be between 1 byte and 10 MB.'; status.className = 'form-status error'; return; }
    const signature = bytesToText(await file.slice(0, 5).arrayBuffer());
    if (signature !== '%PDF-') { status.textContent = 'The selected file does not start with a PDF signature.'; status.className = 'form-status error'; return; }
    const button = $('upload-submit'); button.disabled = true; button.textContent = 'Extracting text…'; status.textContent = 'Reading PDF text locally in this browser; the PDF is not uploaded for extraction.'; status.className = 'form-status';
    let extracted;
    try {
      extracted = await extractPdfTerms(file, (page, total, count) => {
        status.textContent = `Extracting text locally · page ${page.toLocaleString()} of ${total.toLocaleString()} · ${count.toLocaleString()} distinct terms`;
      });
      status.textContent = `Found ${extracted.terms.length.toLocaleString()} terms. Encrypting the PDF and filename locally…`;
      button.textContent = 'Encrypting locally…';
      const nameData = await encryptBytes(textToBytes(file.name), aesKey);
      const contentData = await encryptBytes(extracted.fileBytes, aesKey);
      const tokens = await tokensFor(extracted.terms);
      button.textContent = 'Uploading ciphertext…';
      await api(`${API}/documents`, { method: 'POST', body: JSON.stringify({ encryptedName: nameData.cipher, nameIv: nameData.iv, contentIv: contentData.iv, encryptedContent: contentData.cipher, mediaType: 'application/pdf', sizeBytes: file.size, keywordTokens: tokens }) });
      status.textContent = `Encrypted PDF uploaded; ${tokens.length.toLocaleString()} opaque text terms indexed.${extracted.truncated ? ` The ${MAX_INDEX_TERMS.toLocaleString()}-term indexing cap was reached.` : ''}`; status.className = 'form-status success';
      $('upload-form').reset(); $('file-name').style.display = 'none';
      $('results-description').textContent = 'Latest documents'; await refresh();
    } catch (error) { status.textContent = error.message; status.className = 'form-status error'; }
    finally { if (extracted?.fileBytes) extracted.fileBytes.fill(0); button.disabled = !isUnlocked; button.innerHTML = 'Extract text, encrypt &amp; upload <span>→</span>'; }
  });

  $('search-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!isUnlocked) { $('unlock-error').textContent = 'Unlock the workspace before searching.'; return; }
    const query = $('search-query').value;
    const terms = words(query);
    if (!terms.length) { $('results-description').textContent = 'Enter one or more keywords to search'; return; }
    if (terms.length > 20) { $('results-description').textContent = 'Search with up to 20 distinct words at a time.'; return; }
    const button = event.currentTarget.querySelector('button'); button.disabled = true; button.textContent = 'Searching…';
    try {
      const tokens = await tokensFor(terms);
      const result = await api(`${API}/search`, { method: 'POST', body: JSON.stringify({ tokens }) });
      $('results-description').textContent = `${result.results.length} result${result.results.length === 1 ? '' : 's'} · all ${result.queryTokenCount} term${result.queryTokenCount === 1 ? '' : 's'} matched`;
      $('search-time').textContent = `${result.elapsedMillis} ms server time`;
      await displayDocuments(result.results, true);
    } catch (error) { $('results-description').textContent = error.message; }
    finally { button.disabled = false; button.innerHTML = 'Search <span>→</span>'; }
  });

  $('refresh-button').addEventListener('click', async () => {
    try { await refresh(); } catch (error) { $('results-description').textContent = error.message; }
  });

  async function runExperimentalBenchmarks(documents) {
    const indexedDocuments = [];
    for (const doc of documents.slice(0, 10)) {
      const payload = await api(`${API}/documents/${encodeURIComponent(doc.id)}`);
      const pdfBytes = await decryptBytes(payload.encryptedContent, payload.contentIv, aesKey);
      let extracted;
      try {
        const file = new File([pdfBytes], 'experimental.pdf', { type: payload.mediaType || 'application/pdf' });
        extracted = await extractPdfTerms(file, () => {});
        const tokens = await tokensFor(extracted.terms);
        indexedDocuments.push({ id: doc.id, terms: extracted.terms, tokens });
      } finally {
        pdfBytes.fill(0);
        extracted?.fileBytes.fill(0);
      }
    }

    const scales = [];
    for (const documentCount of [1, 5, 10]) {
      if (documents.length < documentCount) continue;
      const plaintext = new Map();
      const blindIndex = new Map();
      for (const doc of indexedDocuments.slice(0, documentCount)) {
        for (let i = 0; i < doc.terms.length; i++) {
          const add = (map, key) => {
            if (!map.has(key)) map.set(key, []);
            map.get(key).push(doc.id);
          };
          add(plaintext, doc.terms[i]);
          add(blindIndex, doc.tokens[i]);
        }
      }

      const terms = [...plaintext.keys()];
      const queries = Array.from({ length: 400 }, (_, i) => terms[(i * 17 + 5) % terms.length]);
      const blindQueries = await tokensFor(queries);
      const measure = (strategy, index, searchTerms, bytesPerPair) => {
        const lookup = (term) => index.get(term)?.length || 0;
        let checksum = 0;
        for (let i = 0; i < 100; i++) checksum += lookup(searchTerms[i % searchTerms.length]);
        const started = performance.now();
        for (const term of searchTerms) checksum += lookup(term);
        const elapsed = Math.max(0.001, performance.now() - started);
        const averageLookupMicros = Math.round(elapsed * 1000 / searchTerms.length * 100) / 100;
        const indexedPairs = [...index.values()].reduce((total, ids) => total + ids.length, 0);
        if (checksum === Number.MIN_SAFE_INTEGER) throw new Error('Unreachable benchmark checksum.');
        return {
          strategy,
          totalLookupMillis: Math.round(elapsed),
          averageLookupMicros,
          lookupsPerSecond: Math.round(searchTerms.length * 1000 / elapsed),
          estimatedIndexBytes: indexedPairs * bytesPerPair
        };
      };
      const plainResult = measure('Plain keyword Map', plaintext, queries, 24);
      const blindResult = measure('HMAC blind-index Map', blindIndex, blindQueries, 44);
      const storageOverheadPercent = plainResult.estimatedIndexBytes === 0 ? 0
        : Math.round((blindResult.estimatedIndexBytes - plainResult.estimatedIndexBytes) * 10000
          / plainResult.estimatedIndexBytes) / 100;
      scales.push({
        documentCount,
        plaintext: plainResult,
        blindIndex: blindResult,
        storageOverheadPercent
      });
    }
    return { documentCount: documents.length, scales };
  }

  $('benchmark-button').addEventListener('click', async (event) => {
    const button = event.currentTarget; const status = $('benchmark-status'); const target = $('benchmark-results');
    button.disabled = true; button.textContent = 'Running…'; status.textContent = 'Running synthetic lookups and preparing experimental PDF indexes…';
    try {
      const report = await api('/api/benchmarks/run', { method: 'POST', body: '{}' });
      let experimental = { documentCount: 0, scales: [] };
      let experimentalMessage;
      if (!isUnlocked) {
        experimentalMessage = 'Unlock the workspace to run experimental benchmarks on uploaded PDFs.';
      } else {
        try {
          const documents = await api(`${API}/documents`);
          experimental = await runExperimentalBenchmarks(documents);
          if (experimental.documentCount === 0) {
            experimentalMessage = 'No uploaded PDFs are available for experimental benchmarks.';
          } else {
            const availableScales = experimental.scales.map((scale) => scale.documentCount);
            const missingScales = [1, 5, 10].filter((count) => !availableScales.includes(count));
            experimentalMessage = missingScales.length
              ? `Experimental rows use uploaded PDFs; missing scales: ${missingScales.join(', ')} documents.`
              : 'Experimental rows use uploaded PDFs.';
          }
        } catch (error) {
          experimentalMessage = `Experimental benchmark unavailable: ${error.message}`;
        }
      }

      status.textContent = `${report.benchmark} · ${report.searchesPerScale} searches per dataset · ${experimentalMessage}`;
      const table = document.createElement('table'); table.className = 'benchmark-table';
      table.innerHTML = '<thead><tr><th>DATASET</th><th>DOCUMENTS</th><th>PLAIN AVG</th><th>HMAC AVG</th><th>PLAIN INDEX</th><th>HMAC INDEX</th><th>SIZE OVERHEAD</th></tr></thead>';
      const body = document.createElement('tbody');
      const completedExperimentalScales = new Set(experimental.scales.map((scale) => scale.documentCount));
      const experimentalRows = [
        ...experimental.scales,
        ...[1, 5, 10]
          .filter((documentCount) => !completedExperimentalScales.has(documentCount))
          .map((documentCount) => ({ documentCount, unavailable: true }))
      ].sort((a, b) => a.documentCount - b.documentCount);
      const appendRows = (scales, dataset) => {
        for (const scale of scales) {
          const row = document.createElement('tr');
          const values = scale.unavailable
            ? [dataset, scale.documentCount.toLocaleString(), `Upload at least ${scale.documentCount} PDFs`, '—', '—', '—', '—']
            : [dataset, scale.documentCount.toLocaleString(), `${scale.plaintext.averageLookupMicros} μs`, `${scale.blindIndex.averageLookupMicros} μs`, bytesLabel(scale.plaintext.estimatedIndexBytes), bytesLabel(scale.blindIndex.estimatedIndexBytes), `${scale.storageOverheadPercent}%`];
          for (const value of values) { const cell = document.createElement('td'); cell.textContent = value; cell.className = 'mono'; row.append(cell); }
          body.append(row);
        }
      };
      appendRows(experimentalRows, 'Experimental');
      appendRows(report.scales, 'Synthetic');
      if (!body.children.length) {
        const row = document.createElement('tr');
        const cell = document.createElement('td'); cell.colSpan = 7; cell.textContent = 'No benchmark results are available.';
        row.append(cell); body.append(row);
      }
      table.append(body); target.replaceChildren(table);
    } catch (error) { status.textContent = error.message; }
    finally { button.disabled = false; button.innerHTML = 'Run benchmark <span>↗</span>'; }
  });

  const dialog = $('privacy-dialog');
  $('privacy-open').addEventListener('click', () => dialog.showModal());
  $('privacy-link').addEventListener('click', () => dialog.showModal());
  $('privacy-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
  $('search-form').querySelector('button').disabled = true;
})();
