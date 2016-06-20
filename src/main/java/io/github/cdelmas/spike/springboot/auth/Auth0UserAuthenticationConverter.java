/*
   Copyright 2016 Cyril Delmas
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package io.github.cdelmas.spike.springboot.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

public class Auth0UserAuthenticationConverter implements UserAuthenticationConverter {

    private static final List<String> CANDIDATE_NAME_KEYS = asList("email", "user_name", "username", "name", "fullname", "principal");

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(USERNAME, authentication.getName());
        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }

    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {
        return findNameKey(map)
                .map(k -> new UsernamePasswordAuthenticationToken(map.get(k), "N/A", getAuthorities(map)))
                .orElse(null);
    }

    private Optional<String> findNameKey(Map<String, ?> map) {
        return map.keySet().stream()
                .filter(CANDIDATE_NAME_KEYS::contains)
                .sorted((k1, k2) -> Integer.compare(CANDIDATE_NAME_KEYS.indexOf(k1), CANDIDATE_NAME_KEYS.indexOf(k2)))
                .findFirst();
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Map<String, ?> map) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.addAll(extractAuthorities(map, "Roles"));
        authorities.addAll(extractAuthorities(map, "roles"));
        authorities.addAll(extractAuthorities(map, "authorities"));
        authorities.addAll(extractAuthorities(map, "Authorities"));

        return authorities;
    }

    private Collection<GrantedAuthority> extractAuthorities(Map<String, ?> map, String authoritiesKey) {
        List<String> authorities = new ArrayList<>();
        Object rolesObject = map.get(authoritiesKey);
        if (rolesObject != null && rolesObject instanceof Collection) {
            authorities.addAll((Collection<? extends String>) rolesObject);
        }
        return authorities.stream().map(SimpleGrantedAuthority::new).collect(toList());
    }
}
