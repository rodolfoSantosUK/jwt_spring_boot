package io.github.dougllasfps.security.jwt;

import io.github.dougllasfps.service.impl.UsuarioServiceImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthFIlter extends OncePerRequestFilter {


    private JWTService jwtService;
    private UsuarioServiceImpl usuarioService;

    public JwtAuthFIlter(JWTService jwtService, UsuarioServiceImpl usuarioService) {
        this.jwtService = jwtService;
        this.usuarioService = usuarioService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");
        if (authorization != null  && authorization.startsWith("Bearer")) {
                String token = authorization.split(" ")[1];
                boolean isValid = jwtService.tokenValido(token);

                if(isValid) {
                    String loginUsuario = jwtService.obterLoginUsuario(token);
                    UserDetails usuario =  usuarioService.loadUserByUsername(loginUsuario);
                    UsernamePasswordAuthenticationToken user = new
                            UsernamePasswordAuthenticationToken(usuario, null,usuario.getAuthorities());

                    user.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(user);
                }
          }

        filterChain.doFilter(request, response);

    }
}
