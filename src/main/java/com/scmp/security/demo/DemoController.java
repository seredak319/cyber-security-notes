package com.scmp.security.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/user-test")
@PreAuthorize("hasRole('ADMIN')")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello() {
        log.info("Say hello but not a user - only Admin");
        return ResponseEntity.ok("Hello from secured endpoint");
    }

    @GetMapping("/public")
    public ResponseEntity<String> sayHello2() {
        log.info("test");
        return ResponseEntity.ok("Hello from secured endpoint");
    }

}
