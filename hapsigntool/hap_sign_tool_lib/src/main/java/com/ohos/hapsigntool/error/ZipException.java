package com.ohos.hapsigntool.error;

import java.io.IOException;

/**
 * Zip exception for programs.
 *
 * @since 2023/12/07
 */
public class ZipException extends IOException {
    /**
     * new ZipException
     * 
     * @param message exception message
     */
    public ZipException(String message) {
        super(message);
    }

    /**
     * new ZipException
     * 
     * @param message exception message
     * @param e exception
     */
    public ZipException(String message, Exception e) {
        super(message, e);
    }
}
