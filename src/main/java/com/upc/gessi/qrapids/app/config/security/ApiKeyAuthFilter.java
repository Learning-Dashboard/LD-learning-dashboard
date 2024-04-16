package com.upc.gessi.qrapids.app.config.security;

import com.upc.gessi.qrapids.app.domain.models.AppUser;
import com.upc.gessi.qrapids.app.domain.repositories.AppUser.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final UserRepository m_userRepository;
    private final boolean m_enable;

    public ApiKeyAuthFilter(UserRepository userRepository, boolean enable) {
        this.m_userRepository = userRepository;
        this.m_enable = enable;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();

        // Check if the URI contains "/api"
        if (requestUri.contains("/api") && this.m_enable) {

            // Get the API key and secret from request headers
            String requestApiKey = request.getHeader("X-API-KEY");

            if (requestApiKey != null) {

                //Get the username from the request api key
                String username = requestApiKey.substring("apiKey_".length());

                //Get the user with the username to check if exists
                AppUser appUser = this.m_userRepository.findByUsername(username);

                if (appUser == null) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write("Unauthorized");
                } else {
                    filterChain.doFilter(request, response);
                }
            }
            else {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write("Unauthorized");
            }
        }
        else {
            // If the URI does not contain "/api", proceed without filtering
            filterChain.doFilter(request, response);
        }
    }
}
