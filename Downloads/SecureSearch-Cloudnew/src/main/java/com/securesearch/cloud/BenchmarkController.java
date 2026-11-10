package com.securesearch.cloud;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/benchmarks")
public class BenchmarkController {
    private static final int TERMS = 64;
    private static final int SEARCHES = 400;

    public record StrategyResult(String strategy, long totalLookupMillis, double averageLookupMicros,
                                 long lookupsPerSecond, long estimatedIndexBytes) {}
    public record ScaleResult(int documentCount, int indexedPairs, StrategyResult plaintext,
                              StrategyResult blindIndex, double storageOverheadPercent) {}
    public record BenchmarkReport(String benchmark, String note, int searchesPerScale,
                                  List<ScaleResult> scales) {}

    @PostMapping("/run")
    public BenchmarkReport run() {
        List<ScaleResult> results = new ArrayList<>();
        for (int documentCount : new int[]{100, 1_000, 10_000}) results.add(runScale(documentCount));
        return new BenchmarkReport("Synthetic in-memory exact-key lookup",
                "Precomputed lookup only; excludes network, database I/O, client PDF parsing, encryption, and browser costs. Storage figures are rough key/value byte estimates, not database measurements.",
                SEARCHES, results);
    }

    private ScaleResult runScale(int documents) {
        Map<String, List<Integer>> plain = new HashMap<>();
        Map<String, List<Integer>> blind = new HashMap<>();
        int pairs = 0;
        byte[] key = "demo-only benchmark key; not used for uploaded files".getBytes(StandardCharsets.UTF_8);
        for (int id = 0; id < documents; id++) {
            for (int offset = 0; offset < 3; offset++) {
                String term = "topic-" + ((id * 7 + offset * 13) % TERMS);
                plain.computeIfAbsent(term, ignored -> new ArrayList<>()).add(id);
                blind.computeIfAbsent(hmac(key, term), ignored -> new ArrayList<>()).add(id);
                pairs++;
            }
        }
        List<String> queries = new ArrayList<>(SEARCHES);
        for (int i = 0; i < SEARCHES; i++) queries.add("topic-" + ((i * 17 + 5) % TERMS));
        List<String> blindQueries = queries.stream().map(query -> hmac(key, query)).toList();
        StrategyResult p = measure("Plain keyword HashMap", plain, queries, 12 + 4 + 8);
        StrategyResult s = measure("HMAC blind-index HashMap", blind, blindQueries, 32 + 4 + 8);
        double overhead = p.estimatedIndexBytes() == 0 ? 0 : (s.estimatedIndexBytes() - p.estimatedIndexBytes()) * 100.0 / p.estimatedIndexBytes();
        return new ScaleResult(documents, pairs, p, s, Math.round(overhead * 100.0) / 100.0);
    }

    private StrategyResult measure(String name, Map<String, List<Integer>> index, List<String> queries, int bytesPerPair) {
        // Warm up the same code path before recording the timed batch.
        long checksum = 0;
        for (int i = 0; i < 100; i++) checksum += lookup(index, queries.get(i % queries.size()));
        long started = System.nanoTime();
        for (String query : queries) checksum += lookup(index, query);
        long elapsed = Math.max(1, System.nanoTime() - started);
        long millis = elapsed / 1_000_000;
        double micros = elapsed / 1_000.0 / queries.size();
        long perSecond = Math.round(queries.size() * 1_000_000_000.0 / elapsed);
        // Prevent the lookup result from being optimized away.
        if (checksum == Long.MIN_VALUE) throw new IllegalStateException("unreachable");
        return new StrategyResult(name, millis, Math.round(micros * 100.0) / 100.0,
                perSecond, (long) index.values().stream().mapToInt(List::size).sum() * bytesPerPair);
    }

    private int lookup(Map<String, List<Integer>> index, String token) {
        List<Integer> values = index.get(token);
        return values == null ? 0 : values.size();
    }

    private String hmac(byte[] key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] bytes = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }
}
