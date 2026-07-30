package com.aakash.qsec.device;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DeviceServiceTest {

    @Mock
    private DeviceRepository repository;   // a fake repository

    @InjectMocks
    private DeviceService service;          // the real service, with the fake injected

    @Test
    void registerDevice_savesWhenSerialIsNew() {
        // Arrange: pretend no device with this serial exists
        when(repository.existsBySerialNumber("SN-100")).thenReturn(false);
        when(repository.save(any(Device.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        Device result = service.registerDevice("SN-100", "QC-X1");

        // Assert
        assertEquals("SN-100", result.getSerialNumber());
        assertEquals(DeviceStatus.ENROLLED, result.getStatus());
        verify(repository).save(any(Device.class));   // confirm it tried to save
    }

    @Test
    void registerDevice_rejectsDuplicateSerial() {
        // Arrange: pretend the serial already exists
        when(repository.existsBySerialNumber("SN-DUP")).thenReturn(true);

        // Act + Assert: the business rule should throw
        assertThrows(DeviceAlreadyExistsException.class,
                () -> service.registerDevice("SN-DUP", "QC-X1"));

        // And it must NOT attempt to save
        verify(repository, never()).save(any(Device.class));
    }

    @Test
    void updateStatus_rejectsChangingARevokedDevice() {
        // Arrange: a device that is already REVOKED
        Device revoked = new Device("SN-REV", "QC-X1");
        revoked.setStatus(DeviceStatus.REVOKED);
        when(repository.findById(1L)).thenReturn(Optional.of(revoked));

        // Act + Assert: the terminal-revocation rule should throw
        assertThrows(IllegalStateException.class,
                () -> service.updateStatus(1L, DeviceStatus.ACTIVE));
    }

    @Test
    void getDevice_throwsWhenNotFound() {
        // Arrange: repository finds nothing
        when(repository.findById(999L)).thenReturn(Optional.empty());

        // Act + Assert
        assertThrows(DeviceNotFoundException.class,
                () -> service.getDevice(999L));
    }
}
