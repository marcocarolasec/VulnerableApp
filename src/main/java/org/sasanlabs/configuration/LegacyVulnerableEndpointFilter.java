package org.sasanlabs.configuration;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Disables legacy demonstration levels once their secure replacements are available. */
@Component
public class LegacyVulnerableEndpointFilter extends OncePerRequestFilter {

    private static final Map<String, Set<String>> DISABLED_LEVELS = createDisabledLevels();

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String[] segments = request.getServletPath().split("/");
        if (segments.length >= 3
                && DISABLED_LEVELS
                        .getOrDefault(segments[1], Collections.emptySet())
                        .contains(segments[2])) {
            response.sendError(
                    HttpStatus.FORBIDDEN.value(), "This insecure legacy level is disabled");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static Map<String, Set<String>> createDisabledLevels() {
        Map<String, Set<String>> disabled = new HashMap<>();
        disabled.put("AuthenticationVulnerability", levels(2, 8, 10));
        disabled.put("BlindSQLInjectionVulnerability", levels(1, 2));
        disabled.put("CryptographicFailures", levels(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
        disabled.put("Http3xxStatusCodeBasedInjection", levels(1, 2, 3, 4, 5, 6, 7, 9, 10));
        disabled.put("JWTVulnerability", levels(1, 2, 3, 10, 15, 16));
        disabled.put("LDAPInjectionVulnerability", levels(4));
        disabled.put("UnionBasedSQLInjectionVulnerability", levels(1, 2));
        disabled.put("UnrestrictedFileUpload", levels(7));
        disabled.put("XSSInImgTagAttribute", levels(1, 2, 3, 4, 5));
        disabled.put("XXEVulnerability", levels(1, 2));
        return Collections.unmodifiableMap(disabled);
    }

    private static Set<String> levels(Integer... levels) {
        Set<String> result = new HashSet<>();
        Arrays.stream(levels).forEach(level -> result.add("LEVEL_" + level));
        return Collections.unmodifiableSet(result);
    }
}
