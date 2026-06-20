package com.fleetops.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final Logger log = LoggerFactory.getLogger(AuditController.class);

    @PostMapping("/events")
    public ResponseEntity<Void> logEvent(@RequestBody Map<String, Object> event, Authentication auth) {
        // Override user with authenticated principal — never trust client-supplied username
        event.put("user", auth != null ? auth.getName() : "anonymous");
        log.info("[AUDIT] action={} resource={} user={} eventId={} service={} success={} detail={}",
            event.get("action"),
            event.get("resource"),
            event.get("user"),
            event.get("eventId"),
            event.get("service"),
            event.get("success"),
            event.get("detail"));
        return ResponseEntity.accepted().build();
    }
}
