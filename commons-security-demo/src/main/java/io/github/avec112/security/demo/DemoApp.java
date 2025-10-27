package io.github.avec112.security.demo;


import picocli.CommandLine;

@CommandLine.Command(
        name = "commons-security-demo",
        mixinStandardHelpOptions = true,
        version = "1.0-SNAPSHOT",
        description = "Demonstration of commons-security features",
        subcommands = { AesEncryptCommand.class }
)
public class DemoApp implements Runnable {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new DemoApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        System.out.println("Use --help to list available commands.");
    }
}
