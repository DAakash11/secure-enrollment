package com.aakash.qsec.device;

import java.util.List;

import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;

@Service
public class DeviceService {

    private final DeviceRepository repository;

    // Constructor injection — Spring supplies the repository
    public DeviceService(DeviceRepository repository) {
        this.repository = repository;
    }

    // CREATE
    @Transactional
    public Device registerDevice(String serialNumber, String model) {
        if (repository.existsBySerialNumber(serialNumber)) {
            throw new DeviceAlreadyExistsException(serialNumber);
        }
        Device device = new Device(serialNumber, model);
        return repository.save(device);
    }

    // READ (all)
    public List<Device> getAllDevices() {
        return repository.findAll();
    }

    // READ (one)
    public Device getDevice(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new DeviceNotFoundException(id));
    }

    // UPDATE (status transition, with a business rule)
    @Transactional
    public Device updateStatus(Long id, DeviceStatus newStatus) {
        Device device = getDevice(id);

        // Business rule: a revoked device is terminal — it can't be reactivated
        if (device.getStatus() == DeviceStatus.REVOKED) {
            throw new IllegalStateException(
                "Device " + id + " is revoked and cannot change status");
        }

        device.setStatus(newStatus);
        return repository.save(device);
    }

    // DELETE
    @Transactional
    public void deleteDevice(Long id) {
        if (!repository.existsById(id)) {
            throw new DeviceNotFoundException(id);
        }
        repository.deleteById(id);
    }
}
