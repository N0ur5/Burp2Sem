package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Semgrep Passive Scanner");
        api.logging().logToOutput("Semgrep Passive Scanner Extension loaded.");
        api.scanner().registerScanCheck(new SemgrepScanCheck(api));
    }
}
