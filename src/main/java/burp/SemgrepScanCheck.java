package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class SemgrepScanCheck implements ScanCheck {
    private final MontoyaApi api;
    private final ObjectMapper mapper = new ObjectMapper();
  // Replace the rulesDir below with your own directory
    private final String rulesDir = "/home/kali/semgrab/semgrep-rules/javascript/";

    public SemgrepScanCheck(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse rr) {
        String url = rr.request().url();
        api.logging().logToOutput("[Semgrep] passiveAudit for: " + url);

        String ct = rr.response().headers().stream()
                     .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                     .map(HttpHeader::value)
                     .findFirst().orElse("");
        api.logging().logToOutput("[Semgrep]  Content-Type: " + ct);

        List<AuditIssue> issues = new ArrayList<>();
        try {
            String body = rr.response().bodyToString();
            if (ct.toLowerCase().contains("javascript")) {
                issues.addAll(scanJs(rr, url, body));
            } else if (ct.toLowerCase().contains("html")) {
                Document doc = Jsoup.parse(body);
                Elements scripts = doc.select("script:not([src])");
                api.logging().logToOutput("[Semgrep]  Inline scripts: " + scripts.size());
                int idx = 0;
                for (Element s : scripts) {
                    idx++;
                    issues.addAll(scanJs(rr, url + "#inline-" + idx, s.data()));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Semgrep] scan error: " + e.getMessage());
        }

        return auditResult(issues.toArray(new AuditIssue[0]));
    }

    private List<AuditIssue> scanJs(HttpRequestResponse rr, String location, String code) throws Exception {
        File tmp = File.createTempFile("burp-sg-", ".js");
        try (BufferedWriter w = new BufferedWriter(new FileWriter(tmp, StandardCharsets.UTF_8))) {
            w.write(code);
        }

        ProcessBuilder pb = new ProcessBuilder(
            "semgrep",
            "--config", rulesDir,
            "--json",
            tmp.getAbsolutePath()
        );
        Process p = pb.start();
        JsonNode root = mapper.readTree(p.getInputStream());
        p.waitFor();

        List<AuditIssue> result = new ArrayList<>();
        for (JsonNode hit : root.path("results")) {
            String id   = hit.get("check_id").asText();
            String msg  = hit.path("extra").path("message").asText("");
            int    line = hit.path("start").path("line").asInt(-1);
            String loc  = location + "#L" + line;

            // Highlight the entire request/response in yellow with a note
            HttpRequestResponse annotated = rr.withAnnotations(
                Annotations.annotations("Semgrep rule: " + id, HighlightColor.YELLOW)
            );

            result.add(auditIssue(
                id,
                msg,
                "",
                loc,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.CERTAIN,
                "",
                "",
                AuditIssueSeverity.MEDIUM,
                annotated
            ));
        }

        tmp.delete();
        return result;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse rr, AuditInsertionPoint ip) {
        return auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
            ? ConsolidationAction.KEEP_EXISTING
            : ConsolidationAction.KEEP_BOTH;
    }
}
