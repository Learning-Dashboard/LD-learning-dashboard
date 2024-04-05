package com.upc.gessi.qrapids.app.config.security;

import com.upc.gessi.qrapids.app.domain.models.AppUser;
import com.upc.gessi.qrapids.app.domain.repositories.AppUser.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ApiKeyAuthFilter extends OncePerRequestFilter {
    private String apiKey = "apiKey_";
    private final UserRepository m_userRepository;

    public ApiKeyAuthFilter(UserRepository userRepository) {
        this.m_userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();

        // Check if the URI contains "/api"
        if (requestUri.contains("/api")) {

            // Get the API key and secret from request headers
            String requestApiKey = request.getHeader("X-API-KEY");

            if (requestApiKey != null) {

                String username = requestApiKey.substring("apiKey_".length());

                AppUser appUser = this.m_userRepository.findByUsername(username);

                if (appUser == null) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write("Unauthorized");
                } else {
                    filterChain.doFilter(request, response);

                    /*
                    apiKey += username;

                    // Validate the key and secret
                    if (apiKey.equals(requestApiKey)) {
                        // Continue processing the request
                        filterChain.doFilter(request, response);
                    } else {
                        // Reject the request and send an unauthorized error
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.getWriter().write("Unauthorized");
                    }
                    */
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
