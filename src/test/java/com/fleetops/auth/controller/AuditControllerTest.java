package com.fleetops.auth.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuditControllerTest {

    private final AuditController controller = new AuditController();

    @Test
    void logEvent_returns202AndSetsAuthenticatedUser() {
        Map<String, Object> event = new HashMap<>();
        event.put("action", "LOGIN");
        event.put("resource", "/api/auth/login");
        event.put("eventId", "evt-001");
        event.put("service", "auth-service");
        event.put("success", true);
        event.put("detail", "User logged in");

        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("admin1");

        ResponseEntity<Void> result = controller.logEvent(event, auth);

        assertEquals(202, result.getStatusCode().value());
        assertEquals("admin1", event.get("user"));
    }

    @Test
    void logEvent_usesAnonymousWhenNotAuthenticated() {
        Map<String, Object> event = new HashMap<>();
        event.put("action", "HEALTH_CHECK");
        event.put("resource", "/health");
        event.put("eventId", "evt-002");
        event.put("service", "auth-service");
        event.put("success", true);
        event.put("detail", "");

        ResponseEntity<Void> result = controller.logEvent(event, null);

        assertEquals(202, result.getStatusCode().value());
        assertEquals("anonymous", event.get("user"));
    }

    @Test
    void logEvent_sanitizesNewlineInjectionInAction() {
        Map<String, Object> event = new HashMap<>();
        event.put("action", "LOGIN\nINFO: forged-log-entry");
        event.put("resource", "/api");
        event.put("eventId", "evt-003");
        event.put("service", "auth");
        event.put("success", false);
        event.put("detail", "injected\r\nfake-entry");

        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("attacker");

        ResponseEntity<Void> result = controller.logEvent(event, auth);

        assertEquals(202, result.getStatusCode().value());
    }

    @Test
    void logEvent_handlesNullFields() {
        Map<String, Object> event = new HashMap<>();
        event.put("action", null);
        event.put("resource", null);
        event.put("eventId", null);
        event.put("service", null);
        event.put("success", null);
        event.put("detail", null);

        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("user1");

        assertDoesNotThrow(() -> controller.logEvent(event, auth));
    }
}
