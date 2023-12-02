package com.ohos.hapsigntool.error;

import java.io.IOException;

public class ZipException extends IOException {
    public ZipException() {

    }

    public ZipException(String message) {
        super(message);
    }

    public ZipException(String message, Exception e) {
        super(message, e);
    }
}
