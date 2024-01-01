package com.example.keycloak.controller

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@RequestMapping("/api")
class PrivateController {

    @GetMapping("/private")
    fun getPrivate(): ResponseEntity<String> =
            ResponseEntity.ok("Hi. This is endpoint can be accessed only by authenticated user.")

    @PreAuthorize("hasAuthority('reader')")
    @GetMapping("/private/role")
    fun getPrivateWithRole(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<String> {
        return ResponseEntity
                .ok("Hey. Accessed only by authenticated user: ${jwt.getClaim<UUID>("sub")} with default test role.")
    }

}