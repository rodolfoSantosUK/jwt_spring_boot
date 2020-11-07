package io.github.dougllasfps.security.jwt;

import io.github.dougllasfps.VendasApplication;
import io.github.dougllasfps.domain.entity.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;

@Service
public class JWTService {

    private String expiracao = "30";

    private String chaveAssinatura = "cm9kb2xmbw==";

    public String gerarToken(Usuario usuario) {
        long expString = Long.valueOf(expiracao);
        LocalDateTime dataHoraExpiracao = LocalDateTime.now().plusMinutes(expString);
        Instant instant = dataHoraExpiracao.atZone(ZoneId.systemDefault()).toInstant();
        Date data = Date.from(instant);

       // HashMap<String, Object> claims = new HashMap<>();
       // claims.put("emailUsuario", "usuario@gmail.com");

        return Jwts
                .builder()
                .setSubject(usuario.getLogin())
                .setExpiration(data)
         //     .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, chaveAssinatura)
                .compact();
    }

    public Claims obterClaims(String token) throws ExpiredJwtException {
        return Jwts
                .parser()
                .setSigningKey(chaveAssinatura)
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean tokenValido(String token) {
        try {
            Claims claims = obterClaims(token);
            Date dataExpiracao = claims.getExpiration();
            LocalDateTime data = dataExpiracao.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
            return LocalDateTime.now().isBefore(data);

        } catch (Exception e) {
            System.out.println(e);
            return false;
        }
    }

    public String obterLoginUsuario(String token) throws ExpiredJwtException {
        return (String) obterClaims(token).getSubject();

    }

    public static void main(String[] args) {

        ConfigurableApplicationContext context = SpringApplication.run(VendasApplication.class);
        JWTService service =  context.getBean(JWTService.class);
        Usuario usuario = Usuario.builder().login("rodolfo").build();

        String token = service.gerarToken(usuario);
        System.out.println(token);

        boolean isTokenValido = service.tokenValido(token);
        System.out.println("O token está válido? " + isTokenValido);
        System.out.println(service.obterLoginUsuario(token));


    }

}
