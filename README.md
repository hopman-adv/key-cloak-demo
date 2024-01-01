# Keycloak demo
Basic demo to show how use Keycloak (runs in Docker).

Application has 3 REST endpoints:
- public - accessible by everyone
- private - accessible by authenticated user in Keycloak
- private with role - accessible by authenticated user in Keycloak with "reader"

There is Jwt Converter in SecurityConfig which takes roles from Keycloak Jwt token. 
Then it maps Keycloak roles to authorities, therefore hasAuthority can be used on methods.