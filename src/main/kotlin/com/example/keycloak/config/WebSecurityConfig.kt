package com.example.keycloak.config

import com.jayway.jsonpath.JsonPath
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.util.*

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class WebSecurityConfig {
    @Bean
    fun resourceServerFilterChain(
            http: HttpSecurity, customConverter: Converter<Jwt, out AbstractAuthenticationToken>
    ): SecurityFilterChain {
        http {
            oauth2ResourceServer {
                jwt {
                    jwtAuthenticationConverter = customConverter
                }
            }
            cors { configurationSource = corsConfigurationSource("localhost:8081") }
            csrf { disable() }
            sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
            exceptionHandling {
                authenticationEntryPoint = AuthenticationEntryPoint { request, response, authException ->
                    response.apply {
                        addHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"")
                        sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.reasonPhrase)
                    }
                }
            }

            authorizeHttpRequests {
                authorize("/actuator/health/readiness", permitAll)
                authorize("/actuator/health/liveness", "/v3/api-docs/**", permitAll)
                authorize("/v3/api-docs/**", permitAll)
                authorize("/public", permitAll)
                authorize("/api/**", authenticated)
            }
        }
        return http.build()
    }

    private fun corsConfigurationSource(vararg origins: String): UrlBasedCorsConfigurationSource {
        return with(CorsConfiguration()) conf@{
            allowedOrigins = listOf(*origins)
            allowedMethods = listOf("*")
            allowedHeaders = listOf("*")
            exposedHeaders = listOf("*")
            UrlBasedCorsConfigurationSource().apply { registerCorsConfiguration("/**", this@conf) }
        }
    }

    internal class JwtGrantedAuthoritiesConverter : Converter<Jwt, Collection<GrantedAuthority>> {
        override fun convert(jwt: Jwt): Collection<GrantedAuthority> {
            val claimRealm: Any? = JsonPath.read(jwt.claims, "$.realm_access.roles") // odchycení PathNotFoundException
            // val claimResource: Any? = JsonPath.read(jwt.claims, "$.resource_access.roles") // doplnit pro resources

            val roles: List<String> = when (claimRealm) {
                is String -> claimRealm.split(",")
                is Array<*> -> {
                    if (claimRealm.isArrayOf<String>()) {
                        claimRealm.toList() as List<String>
                    } else {
                        emptyList()
                    }
                }

                is MutableCollection<*> -> {
                    val iter = claimRealm.iterator()
                    if (!iter.hasNext()) {
                        emptyList()
                    } else if (iter.next() is String) {
                        (claimRealm as MutableCollection<String>).toList()
                    } else if (iter.next() is MutableCollection<*>) {
                        (claimRealm as MutableCollection<MutableCollection<*>>).toList()
                                .flatMap { collection -> collection.map { it.toString() } }
                    } else {
                        listOf()
                    }
                }

                else -> emptyList()
            }
            println(roles)
            return roles
                    .map { SimpleGrantedAuthority(it) }
        }
    }


    @Component
    internal class CustomJwtAuthenticationConverter : Converter<Jwt, JwtAuthenticationToken> {
        override fun convert(jwt: Jwt): JwtAuthenticationToken {
            val authorities = JwtGrantedAuthoritiesConverter().convert(jwt)
            val username = JsonPath.read<String>(jwt.claims, "preferred_username")
            return JwtAuthenticationToken(jwt, authorities, username)
        }
    }
}