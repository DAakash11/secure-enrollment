package com.aakash.qsec.device;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DeviceController.class)
@WithMockUser  // run these requests as an authenticated user
class DeviceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private DeviceService service;   // the service is faked; we test the web layer

    @Test
    void register_returns201_onSuccess() throws Exception {
        Device saved = new Device("SN-100", "QC-X1");
        when(service.registerDevice(eq("SN-100"), eq("QC-X1"))).thenReturn(saved);

        var body = objectMapper.writeValueAsString(
                new RegisterDeviceRequest("SN-100", "QC-X1"));

        mockMvc.perform(post("/api/devices").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())                       // 201
                .andExpect(jsonPath("$.serialNumber").value("SN-100"))
                .andExpect(jsonPath("$.status").value("ENROLLED"));
    }

    @Test
    void getAll_returns200_withList() throws Exception {
        when(service.getAllDevices()).thenReturn(List.of(
                new Device("SN-1", "QC-X1"),
                new Device("SN-2", "QC-X2")));

        mockMvc.perform(get("/api/devices"))
                .andExpect(status().isOk())                            // 200
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void getOne_returns404_whenMissing() throws Exception {
        when(service.getDevice(999L)).thenThrow(new DeviceNotFoundException(999L));

        mockMvc.perform(get("/api/devices/999"))
                .andExpect(status().isNotFound());                     // 404 via advice
    }

    @Test
    void register_returns409_onDuplicate() throws Exception {
        when(service.registerDevice(any(), any()))
                .thenThrow(new DeviceAlreadyExistsException("SN-DUP"));

        var body = objectMapper.writeValueAsString(
                new RegisterDeviceRequest("SN-DUP", "QC-X1"));

        mockMvc.perform(post("/api/devices").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());                     // 409 via advice
    }
}
