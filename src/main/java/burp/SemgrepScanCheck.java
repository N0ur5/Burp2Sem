package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

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
    private final String rulesDir = "/home/kali/semgrab/semgrep-rules/javascript/browser/security"; // Adjust as needed

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
                int idx = 0;
                for (Element s : scripts) {
                    idx++;
                    issues.addAll(scanJs(rr, url + "#inline-" + idx, s.data()));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Semgrep] scan error: " + e.getMessage());
        }

        return auditResult(issues);
    }

    private List<AuditIssue> scanJs(HttpRequestResponse rr, String location, String code) throws Exception {
        File tmp = File.createTempFile("burp-sg-", ".js");
        try (BufferedWriter w = new BufferedWriter(new FileWriter(tmp, StandardCharsets.UTF_8))) {
            w.write(code);
        }

        ProcessBuilder pb = new ProcessBuilder("semgrep", "--config", rulesDir, "--json", tmp.getAbsolutePath());
        Process p = pb.start();
        JsonNode root = mapper.readTree(p.getInputStream());
        p.waitFor();
        tmp.delete();

        List<AuditIssue> issues = new ArrayList<>();
        for (JsonNode hit : root.path("results")) {
            String id   = hit.get("check_id").asText();
            String msg  = hit.path("extra").path("message").asText("");
            int line    = hit.path("start").path("line").asInt(-1);
            String loc  = location + "#L" + line;

            // Annotate to highlight in Burp (optional)
            HttpRequestResponse annotated = rr.withAnnotations(
                Annotations.annotations("Semgrep rule: " + id, HighlightColor.YELLOW)
            );

            issues.add(auditIssue(
                id,
                msg,
                "",         // Remediation
                loc,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.CERTAIN,
                "", "",     // Background, Remediation Background
                AuditIssueSeverity.MEDIUM,
                List.of(annotated) // ✅ Ensures req/resp tabs appear
            ));
        }

        return issues;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse rr, AuditInsertionPoint ip) {
        return auditResult(); // Passive-only scanner
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
    }
}
