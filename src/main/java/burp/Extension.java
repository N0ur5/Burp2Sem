package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;       // the Montoya entry‐point interface
import burp.api.montoya.scanner.Scanner;

public class Extension implements BurpExtension {
    private static final String NAME = "Semgrep Passive Scanner";

    @Override
    public void initialize(MontoyaApi api) {
        // Set the name in Burp’s UI
        api.extension().setName(NAME);

        // Register your passive ScanCheck
        Scanner scanner = api.scanner();
        scanner.registerScanCheck(new SemgrepScanCheck(api));
    }
}
