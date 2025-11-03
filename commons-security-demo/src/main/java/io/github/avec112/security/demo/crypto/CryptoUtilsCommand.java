package io.github.avec112.security.demo.crypto;

import picocli.CommandLine;

@CommandLine.Command(
        name = "crypto",
        description = "Demonstrates commons-security cryptography features",
        mixinStandardHelpOptions = true,
        subcommands = {
                AesEncryptCommand.class,
                AesDecryptCommand.class/*,
                RsaEncryptCommand.class,
                RsaDecryptCommand.class,
                DigestCommand.class,
                SignCommand.class,
                VerifyCommand.class*/
        }
)
public class CryptoUtilsCommand implements Runnable {

    @Override
    public void run() {
        // show auto-generated help when no subcommand is provided
        new picocli.CommandLine(this).usage(System.out);
    }
}
