package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;      
import burp.api.montoya.scanner.Scanner;

public class Extension implements BurpExtension {
    private static final String NAME = "Semgrep Passive Scanner";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        Scanner scanner = api.scanner();
        scanner.registerScanCheck(new SemgrepScanCheck(api));
    }
}
