package com.securesearch.cloud;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class SecureSearchApiTests {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired SecureDocumentRepository documents;
    @Autowired KeywordIndexRepository index;

    @BeforeEach
    void cleanDatabase() {
        index.deleteAll();
        documents.deleteAll();
    }

    @Test
    void encryptedUploadSupportsAllTermSearchAndDelete() throws Exception {
        String first = upload("a", "b");
        upload("a");

        mvc.perform(post("/api/secure-search/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokens\":[\"" + token('a') + "\",\"" + token('b') + "\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.queryTokenCount").value(2))
                .andExpect(jsonPath("$.results.length()").value(1))
                .andExpect(jsonPath("$.results[0].id").value(first));

        mvc.perform(get("/api/secure-search/documents/{id}", first))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedContent").value("AQIDBA=="))
                .andExpect(jsonPath("$.contentIv").value("AAAAAAAAAAAAAAAA"));

        mvc.perform(delete("/api/secure-search/documents/{id}", first))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/secure-search/documents"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.[0].id").isNotEmpty());
    }

    @Test
    void rejectsMalformedSearchTokens() throws Exception {
        mvc.perform(post("/api/secure-search/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokens\":[\"plaintext-keyword\"]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void acceptsLargeAutomaticPdfTextIndexes() throws Exception {
        List<String> tokens = java.util.stream.IntStream.range(0, 101)
                .mapToObj(i -> String.format("%064x", i))
                .toList();
        SecureSearchDtos.UploadRequest request = new SecureSearchDtos.UploadRequest(
                "ZmlsZS5wZGY=", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "AQIDBA==",
                "application/pdf", 4, tokens);

        mvc.perform(post("/api/secure-search/documents")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.indexedTokenCount").value(101));
    }

    @Test
    void benchmarkReturnsRequestedSyntheticScalesAndStatesItsScope() throws Exception {
        mvc.perform(post("/api/benchmarks/run").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scales.length()").value(3))
                .andExpect(jsonPath("$.scales[0].documentCount").value(100))
                .andExpect(jsonPath("$.scales[1].documentCount").value(1000))
                .andExpect(jsonPath("$.scales[2].documentCount").value(10000))
                .andExpect(jsonPath("$.note").value(org.hamcrest.Matchers.containsString("excludes network")));
    }

    private String upload(String... tokenIds) throws Exception {
        List<String> tokens = java.util.Arrays.stream(tokenIds).map(id -> token(id.charAt(0))).toList();
        String json = objectMapper.writeValueAsString(new SecureSearchDtos.UploadRequest(
                "ZmlsZS5wZGY=", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "AQIDBA==",
                "application/pdf", 4, tokens));
        MvcResult result = mvc.perform(post("/api/secure-search/documents")
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        return response.get("id").asText();
    }

    private String token(char marker) { return String.valueOf(marker).repeat(64); }
}
