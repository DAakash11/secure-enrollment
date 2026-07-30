package com.aakash.qsec.device;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceService service;

    public DeviceController(DeviceService service) {
        this.service = service;
    }

    // CREATE — POST /api/devices
    @PostMapping
    public ResponseEntity<Device> register(@RequestBody RegisterDeviceRequest request) {
        Device device = service.registerDevice(request.serialNumber(), request.model());
        return ResponseEntity.status(HttpStatus.CREATED).body(device);
    }

    // READ all — GET /api/devices
    @GetMapping
    public List<Device> getAll() {
        return service.getAllDevices();
    }

    // READ one — GET /api/devices/{id}
    @GetMapping("/{id}")
    public Device getOne(@PathVariable Long id) {
        return service.getDevice(id);
    }

    // UPDATE status — PATCH /api/devices/{id}/status
    @PatchMapping("/{id}/status")
    public Device updateStatus(@PathVariable Long id,
                               @RequestBody UpdateStatusRequest request) {
        return service.updateStatus(id, request.status());
    }

    // DELETE — DELETE /api/devices/{id}
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.deleteDevice(id);
        return ResponseEntity.noContent().build();
    }
}
