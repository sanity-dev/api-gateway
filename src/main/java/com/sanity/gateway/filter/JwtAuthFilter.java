package com.sanity.gateway.filter;

import com.sanity.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Filtro global que:
 * 1. Deja pasar las rutas públicas sin validación (login, register, etc.)
 * 2. Valida el JWT para todas las demás rutas
 * 3. Inyecta headers X-User-Email para que los microservicios
 *    downstream conozcan al usuario autenticado SIN necesidad de validar JWT
 */
@Slf4j
@Component
@ConfigurationProperties(prefix = "gateway")
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;
    private List<String> openEndpoints = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/register-therapist",
            "/api/auth/google",
            "/api/auth/forgot-password"
    );

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // Setter para que Spring Boot inyecte la lista desde application.yml
    public void setOpenEndpoints(List<String> openEndpoints) {
        this.openEndpoints = openEndpoints;
    }

    public List<String> getOpenEndpoints() {
        return openEndpoints;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Permitir rutas públicas sin token
        if (isOpenEndpoint(path)) {
            return chain.filter(exchange);
        }

        // Verificar que existe el header Authorization
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Token de autenticación no proporcionado", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        // Validar el JWT
        try {
            Claims claims = jwtUtil.validateToken(token);
            String userEmail = claims.getSubject();

            // Inyectar info del usuario en headers para los microservicios downstream
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Email", userEmail)
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("Token JWT expirado: {}", e.getMessage());
            return onError(exchange, "Token expirado", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("Error validando token JWT: {}", e.getMessage());
            return onError(exchange, "Token inválido", HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isOpenEndpoint(String path) {
        return openEndpoints.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add("Content-Type", "application/json");
        String body = "{\"error\": \"" + message + "\"}";
        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(body.getBytes()))
        );
    }
}

