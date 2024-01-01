package com.example.keycloak

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KeyCloakApplication

fun main(args: Array<String>) {
	runApplication<KeyCloakApplication>(*args)
}
