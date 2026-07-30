package com.aakash.qsec.device;

public class DeviceAlreadyExistsException extends RuntimeException {
    public DeviceAlreadyExistsException(String serialNumber) {
        super("Device already exists with serial number: " + serialNumber);
    }
}
