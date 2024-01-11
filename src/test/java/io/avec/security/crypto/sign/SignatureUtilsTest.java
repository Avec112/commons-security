package io.avec.security.crypto.sign;

import io.avec.security.crypto.BouncyCastleProviderInitializer;
import io.avec.security.crypto.rsa.KeySize;
import io.avec.security.crypto.rsa.RsaCipherTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.KeyPair;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureUtilsTest extends BouncyCastleProviderInitializer {

    @ParameterizedTest
    @CsvSource({
            "1024, eqPI2whf3kkxrU/o6YEA1JnK/+6zLb2c56qJYcIl/D61uSlTCr70yhZHvFrcTy6hm6kNtx5QXfworpjaWk2RpwxLs0li8d++W6zaOMYdadwAGd7xda81lWaHVMwiDNfqUJTc+llDo2UG0ZwfI8ZzqNXlHV84UrDGdsazQgBE7tg=",
            "2048, Ruzjgzwee3HtBusjVQz1d3P9k2EA2M2tVMfsgvTNUVPF0zNpxOrvzlElPqVdkwWL/PrehbPaict3FIFWgWddZArLtomFmCkgfVbVgqtUA+ZkWDcnF0zsUCOyywECibkdj4vG7bMTBk8OtWd2uVGs4DI2RAum5sTjKC5HTmyCgkeF/foaeJSgo0wvozfYHxkHzfh0lb/joBcDJIWl3BSZJAfvW174bCF0bewSPSMQFHgY8gC0Z4nviPlE3nKYbC6WF+sH1hMP7rh0L/YkzqRN8R2jMvFIrZVb2RbQ6c9QH1cgn0hmzuitxaCAkNw2+wtaVGrfIaSBY7CdwN83c4I3oQ==",
            "3072, bH0xfuDdki+teFVxcGi3UPvxQuUah8itW60PTjh1+e3ZN3nqx9+P30pMxqhTZbboLdbsF6BSgM5CBOFAxVWuQTCUtEhYIntoYzcTOmGkxAH93NDScMFVUISCFHxV4JNwlQ3SGNKpk8HSyKrPbtWHiXIQDuaexC3PebVlX+WIBwt55EpLrdik1+4jYKxoZ/iVB2n3lLVZFgCPAJYxkVOim6lup2Km6m8IpW//v3MtEKi8QNE/gPsDNtTuS+7+V0RFzu5ockBqPo4daMAX7xWCr/JOoYgT0bk3kf6mrxdJvE+4xKAtlei8mIfr21Qw7ALXyXO39WMQWCWKU5C0OenEw032Kq3V1v+P3YffQBEi6YL5dfUaG+PFDXeq5FEiv8B//I060w/XrdmN5UDJOnVJXilD9IfeMpVIwvYg8fvWjhMIedpgmwFyhfFHMqet2Go8t2w1CPhmPc1mlHNJuahLzaP9/V40LRgmPapoOm+k8r98c+LTfk+z+7s60HkPpAgC",
            "4096, T51H2WOpKmLe+NI/AUe+NLYW21cWMo/jRISkjxEq+8iE0WH2KGKrhAc0LrzVDgnKJThQi6rHtLeVdm8CIa9gf4SK7w59vpWfWINtBQZ0p40MPW+LbXMJTsTkegY/AEyC0O3wx9VVKmzHQndQtdeyWlbLPFaKEhypjaauooq/2cJ2hIax8ubxaXA82j+vFyRm02YSpdYjOH0XWLfcK7glUQQ/Irnws9T4dMVYMJnB6vu7WJo2gKzQSkmRDN7ur3I+z75hCfBLcet18q/z5dBW+Y/S/dJ+XHfhMhqAsMDZbQSH8gYkIRszaOiMUUK/oRvrk25Ype34Q4uLx9AUTxGAjTEK1EzCZShQPAwXLvXOjE0sBs0avkRcuY8yjaEk1ZMjwJGRCiEeAcgvXc7EfoVRyl61sJdVLdqqQGwP0gXPGwxGa/inWfyOgUt0HWXm+G2qAHRt0DrVK81xUYI1EFFt6btqDdAXE75oJ0FpwOorofZKkKIYi+BefAyTroqR14nA2EqyAyQr+5j2SVl74mSThm4LcOfFvaDV30X05BUtSay0KSMl6TBizCU+xfgKOniSN8qlsbmXUqfkyEw9cBGr9Qw6GcfP2pTMhzEkIZNcfG1LCXnUxkW1MW8f4ur0veiPek0qKV1Mjx6P/etkF7aSyvvvLFPGDwMPwa7DI96qM88="
    })
    void signString(int keySize, String expected) throws Exception {
        // Arrange
        KeyPair keyPair = RsaCipherTest.loadKeyPair(KeySize.getKeySize(keySize));

        // Act
        final byte[] signature = SignatureUtils.sign("Testing", keyPair.getPrivate());

        // Assert
        assertEquals(expected, Base64.getEncoder().encodeToString(signature));
    }

    @ParameterizedTest
    @CsvSource({
            "1024, eqPI2whf3kkxrU/o6YEA1JnK/+6zLb2c56qJYcIl/D61uSlTCr70yhZHvFrcTy6hm6kNtx5QXfworpjaWk2RpwxLs0li8d++W6zaOMYdadwAGd7xda81lWaHVMwiDNfqUJTc+llDo2UG0ZwfI8ZzqNXlHV84UrDGdsazQgBE7tg=",
            "2048, Ruzjgzwee3HtBusjVQz1d3P9k2EA2M2tVMfsgvTNUVPF0zNpxOrvzlElPqVdkwWL/PrehbPaict3FIFWgWddZArLtomFmCkgfVbVgqtUA+ZkWDcnF0zsUCOyywECibkdj4vG7bMTBk8OtWd2uVGs4DI2RAum5sTjKC5HTmyCgkeF/foaeJSgo0wvozfYHxkHzfh0lb/joBcDJIWl3BSZJAfvW174bCF0bewSPSMQFHgY8gC0Z4nviPlE3nKYbC6WF+sH1hMP7rh0L/YkzqRN8R2jMvFIrZVb2RbQ6c9QH1cgn0hmzuitxaCAkNw2+wtaVGrfIaSBY7CdwN83c4I3oQ==",
            "3072, bH0xfuDdki+teFVxcGi3UPvxQuUah8itW60PTjh1+e3ZN3nqx9+P30pMxqhTZbboLdbsF6BSgM5CBOFAxVWuQTCUtEhYIntoYzcTOmGkxAH93NDScMFVUISCFHxV4JNwlQ3SGNKpk8HSyKrPbtWHiXIQDuaexC3PebVlX+WIBwt55EpLrdik1+4jYKxoZ/iVB2n3lLVZFgCPAJYxkVOim6lup2Km6m8IpW//v3MtEKi8QNE/gPsDNtTuS+7+V0RFzu5ockBqPo4daMAX7xWCr/JOoYgT0bk3kf6mrxdJvE+4xKAtlei8mIfr21Qw7ALXyXO39WMQWCWKU5C0OenEw032Kq3V1v+P3YffQBEi6YL5dfUaG+PFDXeq5FEiv8B//I060w/XrdmN5UDJOnVJXilD9IfeMpVIwvYg8fvWjhMIedpgmwFyhfFHMqet2Go8t2w1CPhmPc1mlHNJuahLzaP9/V40LRgmPapoOm+k8r98c+LTfk+z+7s60HkPpAgC",
            "4096, T51H2WOpKmLe+NI/AUe+NLYW21cWMo/jRISkjxEq+8iE0WH2KGKrhAc0LrzVDgnKJThQi6rHtLeVdm8CIa9gf4SK7w59vpWfWINtBQZ0p40MPW+LbXMJTsTkegY/AEyC0O3wx9VVKmzHQndQtdeyWlbLPFaKEhypjaauooq/2cJ2hIax8ubxaXA82j+vFyRm02YSpdYjOH0XWLfcK7glUQQ/Irnws9T4dMVYMJnB6vu7WJo2gKzQSkmRDN7ur3I+z75hCfBLcet18q/z5dBW+Y/S/dJ+XHfhMhqAsMDZbQSH8gYkIRszaOiMUUK/oRvrk25Ype34Q4uLx9AUTxGAjTEK1EzCZShQPAwXLvXOjE0sBs0avkRcuY8yjaEk1ZMjwJGRCiEeAcgvXc7EfoVRyl61sJdVLdqqQGwP0gXPGwxGa/inWfyOgUt0HWXm+G2qAHRt0DrVK81xUYI1EFFt6btqDdAXE75oJ0FpwOorofZKkKIYi+BefAyTroqR14nA2EqyAyQr+5j2SVl74mSThm4LcOfFvaDV30X05BUtSay0KSMl6TBizCU+xfgKOniSN8qlsbmXUqfkyEw9cBGr9Qw6GcfP2pTMhzEkIZNcfG1LCXnUxkW1MW8f4ur0veiPek0qKV1Mjx6P/etkF7aSyvvvLFPGDwMPwa7DI96qM88="
    })
    void verifyString(int keySize, String signature) throws Exception {
        // Arrange
        KeyPair keyPair = RsaCipherTest.loadKeyPair(KeySize.getKeySize(keySize));

        // Act
        byte [] signatureDecoded = Base64.getDecoder().decode(signature);
        boolean verified = SignatureUtils.verify(signatureDecoded, "Testing", keyPair.getPublic());

        // Assert
        assertTrue(verified, "Signature not verified");

    }


    @ParameterizedTest
    @CsvSource({
            "1024, eqPI2whf3kkxrU/o6YEA1JnK/+6zLb2c56qJYcIl/D61uSlTCr70yhZHvFrcTy6hm6kNtx5QXfworpjaWk2RpwxLs0li8d++W6zaOMYdadwAGd7xda81lWaHVMwiDNfqUJTc+llDo2UG0ZwfI8ZzqNXlHV84UrDGdsazQgBE7tg=",
            "2048, Ruzjgzwee3HtBusjVQz1d3P9k2EA2M2tVMfsgvTNUVPF0zNpxOrvzlElPqVdkwWL/PrehbPaict3FIFWgWddZArLtomFmCkgfVbVgqtUA+ZkWDcnF0zsUCOyywECibkdj4vG7bMTBk8OtWd2uVGs4DI2RAum5sTjKC5HTmyCgkeF/foaeJSgo0wvozfYHxkHzfh0lb/joBcDJIWl3BSZJAfvW174bCF0bewSPSMQFHgY8gC0Z4nviPlE3nKYbC6WF+sH1hMP7rh0L/YkzqRN8R2jMvFIrZVb2RbQ6c9QH1cgn0hmzuitxaCAkNw2+wtaVGrfIaSBY7CdwN83c4I3oQ==",
            "3072, bH0xfuDdki+teFVxcGi3UPvxQuUah8itW60PTjh1+e3ZN3nqx9+P30pMxqhTZbboLdbsF6BSgM5CBOFAxVWuQTCUtEhYIntoYzcTOmGkxAH93NDScMFVUISCFHxV4JNwlQ3SGNKpk8HSyKrPbtWHiXIQDuaexC3PebVlX+WIBwt55EpLrdik1+4jYKxoZ/iVB2n3lLVZFgCPAJYxkVOim6lup2Km6m8IpW//v3MtEKi8QNE/gPsDNtTuS+7+V0RFzu5ockBqPo4daMAX7xWCr/JOoYgT0bk3kf6mrxdJvE+4xKAtlei8mIfr21Qw7ALXyXO39WMQWCWKU5C0OenEw032Kq3V1v+P3YffQBEi6YL5dfUaG+PFDXeq5FEiv8B//I060w/XrdmN5UDJOnVJXilD9IfeMpVIwvYg8fvWjhMIedpgmwFyhfFHMqet2Go8t2w1CPhmPc1mlHNJuahLzaP9/V40LRgmPapoOm+k8r98c+LTfk+z+7s60HkPpAgC",
            "4096, T51H2WOpKmLe+NI/AUe+NLYW21cWMo/jRISkjxEq+8iE0WH2KGKrhAc0LrzVDgnKJThQi6rHtLeVdm8CIa9gf4SK7w59vpWfWINtBQZ0p40MPW+LbXMJTsTkegY/AEyC0O3wx9VVKmzHQndQtdeyWlbLPFaKEhypjaauooq/2cJ2hIax8ubxaXA82j+vFyRm02YSpdYjOH0XWLfcK7glUQQ/Irnws9T4dMVYMJnB6vu7WJo2gKzQSkmRDN7ur3I+z75hCfBLcet18q/z5dBW+Y/S/dJ+XHfhMhqAsMDZbQSH8gYkIRszaOiMUUK/oRvrk25Ype34Q4uLx9AUTxGAjTEK1EzCZShQPAwXLvXOjE0sBs0avkRcuY8yjaEk1ZMjwJGRCiEeAcgvXc7EfoVRyl61sJdVLdqqQGwP0gXPGwxGa/inWfyOgUt0HWXm+G2qAHRt0DrVK81xUYI1EFFt6btqDdAXE75oJ0FpwOorofZKkKIYi+BefAyTroqR14nA2EqyAyQr+5j2SVl74mSThm4LcOfFvaDV30X05BUtSay0KSMl6TBizCU+xfgKOniSN8qlsbmXUqfkyEw9cBGr9Qw6GcfP2pTMhzEkIZNcfG1LCXnUxkW1MW8f4ur0veiPek0qKV1Mjx6P/etkF7aSyvvvLFPGDwMPwa7DI96qM88="
    })
    void signBytes(int keySize, String expected) throws Exception {
        // Arrange
        KeyPair keyPair = RsaCipherTest.loadKeyPair(KeySize.getKeySize(keySize));
        final byte[] data = "Testing".getBytes();

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair.getPrivate());

        // Assert
        assertEquals(expected, Base64.getEncoder().encodeToString(signature));
    }

    @ParameterizedTest
    @CsvSource({
            "1024, eqPI2whf3kkxrU/o6YEA1JnK/+6zLb2c56qJYcIl/D61uSlTCr70yhZHvFrcTy6hm6kNtx5QXfworpjaWk2RpwxLs0li8d++W6zaOMYdadwAGd7xda81lWaHVMwiDNfqUJTc+llDo2UG0ZwfI8ZzqNXlHV84UrDGdsazQgBE7tg=",
            "2048, Ruzjgzwee3HtBusjVQz1d3P9k2EA2M2tVMfsgvTNUVPF0zNpxOrvzlElPqVdkwWL/PrehbPaict3FIFWgWddZArLtomFmCkgfVbVgqtUA+ZkWDcnF0zsUCOyywECibkdj4vG7bMTBk8OtWd2uVGs4DI2RAum5sTjKC5HTmyCgkeF/foaeJSgo0wvozfYHxkHzfh0lb/joBcDJIWl3BSZJAfvW174bCF0bewSPSMQFHgY8gC0Z4nviPlE3nKYbC6WF+sH1hMP7rh0L/YkzqRN8R2jMvFIrZVb2RbQ6c9QH1cgn0hmzuitxaCAkNw2+wtaVGrfIaSBY7CdwN83c4I3oQ==",
            "3072, bH0xfuDdki+teFVxcGi3UPvxQuUah8itW60PTjh1+e3ZN3nqx9+P30pMxqhTZbboLdbsF6BSgM5CBOFAxVWuQTCUtEhYIntoYzcTOmGkxAH93NDScMFVUISCFHxV4JNwlQ3SGNKpk8HSyKrPbtWHiXIQDuaexC3PebVlX+WIBwt55EpLrdik1+4jYKxoZ/iVB2n3lLVZFgCPAJYxkVOim6lup2Km6m8IpW//v3MtEKi8QNE/gPsDNtTuS+7+V0RFzu5ockBqPo4daMAX7xWCr/JOoYgT0bk3kf6mrxdJvE+4xKAtlei8mIfr21Qw7ALXyXO39WMQWCWKU5C0OenEw032Kq3V1v+P3YffQBEi6YL5dfUaG+PFDXeq5FEiv8B//I060w/XrdmN5UDJOnVJXilD9IfeMpVIwvYg8fvWjhMIedpgmwFyhfFHMqet2Go8t2w1CPhmPc1mlHNJuahLzaP9/V40LRgmPapoOm+k8r98c+LTfk+z+7s60HkPpAgC",
            "4096, T51H2WOpKmLe+NI/AUe+NLYW21cWMo/jRISkjxEq+8iE0WH2KGKrhAc0LrzVDgnKJThQi6rHtLeVdm8CIa9gf4SK7w59vpWfWINtBQZ0p40MPW+LbXMJTsTkegY/AEyC0O3wx9VVKmzHQndQtdeyWlbLPFaKEhypjaauooq/2cJ2hIax8ubxaXA82j+vFyRm02YSpdYjOH0XWLfcK7glUQQ/Irnws9T4dMVYMJnB6vu7WJo2gKzQSkmRDN7ur3I+z75hCfBLcet18q/z5dBW+Y/S/dJ+XHfhMhqAsMDZbQSH8gYkIRszaOiMUUK/oRvrk25Ype34Q4uLx9AUTxGAjTEK1EzCZShQPAwXLvXOjE0sBs0avkRcuY8yjaEk1ZMjwJGRCiEeAcgvXc7EfoVRyl61sJdVLdqqQGwP0gXPGwxGa/inWfyOgUt0HWXm+G2qAHRt0DrVK81xUYI1EFFt6btqDdAXE75oJ0FpwOorofZKkKIYi+BefAyTroqR14nA2EqyAyQr+5j2SVl74mSThm4LcOfFvaDV30X05BUtSay0KSMl6TBizCU+xfgKOniSN8qlsbmXUqfkyEw9cBGr9Qw6GcfP2pTMhzEkIZNcfG1LCXnUxkW1MW8f4ur0veiPek0qKV1Mjx6P/etkF7aSyvvvLFPGDwMPwa7DI96qM88="
    })
    void verifyBytes(int keySize, String signature) throws Exception {
        // Arrange
        KeyPair keyPair = RsaCipherTest.loadKeyPair(KeySize.getKeySize(keySize));
        final byte[] data = "Testing".getBytes();

        // Act
        byte [] signatureDecoded = Base64.getDecoder().decode(signature);
        boolean verified = SignatureUtils.verify(signatureDecoded, data, keyPair.getPublic());

        // Assert
        assertTrue(verified, "Signature not verified");

    }
}