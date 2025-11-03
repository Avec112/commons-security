package io.github.avec112.security.demo;


import io.github.avec112.security.demo.crypto.CryptoUtilsCommand;
import picocli.CommandLine;

import java.io.InputStream;

@CommandLine.Command(
        name = "commons-security-demo",
        mixinStandardHelpOptions = true,
//        version = "1.0-SNAPSHOT",
        versionProvider = DemoApp.VersionProvider.class,
        description = "Demonstration of commons-security features",
        subcommands = { CryptoUtilsCommand.class }
)
public class DemoApp implements Runnable {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new DemoApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        new CommandLine(this).usage(System.out);
    }

    static class VersionProvider implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            try (InputStream in = getClass().getResourceAsStream("/version.txt")) {
                if (in == null) {
                    return new String[]{"Unknown (version.txt not found)"};
                }
                return new String[]{new String(in.readAllBytes()).trim()};
            } catch (Exception e) {
                return new String[]{"Unknown (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")"};
            }
        }
    }
}
