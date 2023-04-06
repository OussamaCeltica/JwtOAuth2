package com.example.OAuthTest.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Component
public class JwtAuthentificationFilter extends OncePerRequestFilter {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader= request.getHeader(Constants.HEADER_STRING);
        String username=null;
        String token=null;

        if(request.getMethod().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request,response);
        }else {
            if(authHeader != null && authHeader.startsWith(Constants.TOKEN_PREFIX)){
                token=authHeader.replace(Constants.TOKEN_PREFIX,"");
                username=jwtUtils.extractUsername(token);
            }

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
                if(jwtUtils.validateToken(token,username)){
                    UserDetails userDetails= userDetailsService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken auth= new UsernamePasswordAuthenticationToken(userDetails,null, Arrays.asList(new GrantedAuthority() {
                        @Override
                        public String getAuthority() {
                            return "ADMIN";
                        }
                    }));
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);

                }
            }
            filterChain.doFilter(request,response);
        }
    }
}
