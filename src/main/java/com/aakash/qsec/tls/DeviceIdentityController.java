package com.aakash.qsec.tls;

import java.security.cert.X509Certificate;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class DeviceIdentityController {

    @GetMapping("/whoami")
    public String whoami(HttpServletRequest request) {
        // The client cert from the TLS handshake is on the request
        X509Certificate[] certs =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0) {
            return "No client certificate presented.";
        }

        // The leaf (client's own) certificate is first in the chain
        X509Certificate clientCert = certs[0];
        String subject = clientCert.getSubjectX500Principal().getName();
        String issuer = clientCert.getIssuerX500Principal().getName();
        String serial = clientCert.getSerialNumber().toString();

        return "Authenticated device:\n"
                + "  Subject: " + subject + "\n"
                + "  Issued by: " + issuer + "\n"
                + "  Serial: " + serial;
    }
}
