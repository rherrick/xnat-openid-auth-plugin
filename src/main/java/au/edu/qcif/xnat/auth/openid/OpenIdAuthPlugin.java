/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.framework.services.SerializerService;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xnat.security.XnatSecurityExtension;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * XNAT Authentication plugin.
 *
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 */
@XnatPlugin(value = "xnat-openid-auth-plugin", name = "XNAT OpenID Authentication Provider Plugin")
@EnableOAuth2Client
@Component
@Slf4j
public class OpenIdAuthPlugin implements XnatSecurityExtension {
    @Autowired
    public OpenIdAuthPlugin(final AuthenticationProviderConfigurationLocator locator, final SiteConfigPreferences preferences, final SerializerService serializer) {
        _properties = loadProviderProperties(locator);
        _enabledProviders = Arrays.asList(getProperty("enabled").split(","));
        _siteUrl = getSiteUrl(preferences);
        _serializer = serializer;

        INSTANCE = this;
    }

    @SuppressWarnings("unused")
    public static String getLoginStr() {
        return StringUtils.join(Lists.transform(INSTANCE.getEnabledProviders(), new Function<String, String>() {
            @Nullable
            @Override
            public String apply(final String provider) {
                return INSTANCE.getProperty(provider, "link");
            }
        }));
    }

    @SuppressWarnings("unused")
    public static String getUsernamePasswordStyle() {
        return Boolean.parseBoolean(INSTANCE.getProperty("disableUsernamePasswordLogin", "false")) ? "display:none" : "";
    }

    @Override
    public String getAuthMethod() {
        return PROVIDER_ID;
    }

    @Override
    public void configure(final HttpSecurity http) {
        log.debug("Configuring HTTP security for the OpenID plugin: adding OAuth2ClientContextFilter and OpenIdConnectFilter");
        http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
            .addFilterAfter(openIdConnectFilter(), OAuth2ClientContextFilter.class);
    }

    @Override
    public void configure(final AuthenticationManagerBuilder builder) {
        log.debug("Configuring authentication manager for the OpenID plugin: no op");
    }

    @Bean
    @Scope("prototype")
    @DependsOn("xnatOAuth2RestTemplate")
    public OpenIdConnectFilter openIdConnectFilter() {
        log.error("Now creating openIdConnectFilter");
        return new OpenIdConnectFilter(this, _oAuth2RestTemplate, _serializer);
    }

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate xnatOAuth2RestTemplate(final OAuth2ClientContext clientContext) {
        log.debug("At create rest template...");
        final HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        // Interrogate request to get providerId (e.g. look at url if nothing else)
        final String providerId = request.getParameter("providerId");
        log.debug("Provider ID is: {}", providerId);
        request.getSession().setAttribute("providerId", providerId);

        return _oAuth2RestTemplate = new OAuth2RestTemplate(getProtectedResourceDetails(providerId), clientContext);
    }

    public List<String> getEnabledProviders() {
        return _enabledProviders;
    }

    public boolean isEnabled(final String providerId) {
        return _enabledProviders.contains(providerId);
    }

    public String getProperty(final String property) {
        return getProperty(property, null);
    }

    public String getProperty(final String property, final String defaultValue) {
        return _properties.getProperty(property, defaultValue);
    }

    private OAuth2ProtectedResourceDetails getProtectedResourceDetails(final String providerId) {
        final String grantType = getProperty("grantType", "authorization_code");

        final BaseOAuth2ProtectedResourceDetails details;
        switch (grantType) {
            case "implicit":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ImplicitResourceDetails");
                details = new ImplicitResourceDetails();
                break;

            case "client_credentials":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ClientCredentialsResourceDetails");
                details = new ClientCredentialsResourceDetails();
                break;

            case "authorization_code":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as AuthorizationCodeResourceDetails");
                details = new AuthorizationCodeResourceDetails();
                break;

            case "password":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ResourceOwnerPasswordResourceDetails");
                details = new ResourceOwnerPasswordResourceDetails();
                break;

            default:
                throw new RuntimeException("Unknown grant type: " + grantType);
        }

        final String   clientId          = getProperty("clientId");
        final String   clientSecret      = getProperty("clientSecret");
        final String   accessTokenUri    = getProperty("accessTokenUri");
        final String   userAuthUri       = getProperty("userAuthUri");
        final String   tokenName         = getProperty("tokenName");
        final String   preEstablishedUri = getSiteUrl() + getProperty("preEstablishedRedirUri");
        final String[] scopes            = getProperty("scopes").split(",");

        log.debug("Creating protected resource details of provider: {}\nid: {}\nclientId: {}\nclientSecret: {}\naccessTokenUri: {}\nuserAuthUri: {}\ntokenName: {}\npreEstablishedUri: {}\nscopes: {}", providerId, clientId, clientSecret, accessTokenUri, userAuthUri, tokenName, preEstablishedUri, scopes);

        details.setId(providerId);
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setTokenName(tokenName);
        details.setScope(Arrays.asList(scopes));

        if (AbstractRedirectResourceDetails.class.isAssignableFrom(details.getClass())) {
            final AbstractRedirectResourceDetails redirect = (AbstractRedirectResourceDetails) details;
            redirect.setUserAuthorizationUri(userAuthUri);
            redirect.setPreEstablishedRedirectUri(preEstablishedUri);
            redirect.setUseCurrentUri(false);
        } else if (details instanceof ResourceOwnerPasswordResourceDetails) {
            final ResourceOwnerPasswordResourceDetails password = (ResourceOwnerPasswordResourceDetails) details;
            password.setUsername(getProperty("username"));
            password.setPassword(getProperty("password"));
        }
        return details;
    }

    private Properties loadProviderProperties(final AuthenticationProviderConfigurationLocator locator) {
        final Map<String, ProviderAttributes> openIdProviders = locator.getProviderDefinitionsByAuthMethod("openid");
        if (openIdProviders.isEmpty()) {
            throw new RuntimeException("You must configure an OpenID provider");
        }
        if (openIdProviders.size() > 1) {
            throw new RuntimeException("This plugin currently only supports one OpenID provider at a time, but I found " + openIdProviders.size() + " providers defined: " + StringUtils.join(openIdProviders.keySet(), ", "));
        }
        final ProviderAttributes providerDefinition = locator.getProviderDefinition(openIdProviders.keySet().iterator().next());
        assert providerDefinition != null;
        return providerDefinition.getProperties();
    }

    private String getSiteUrl() {
        return _siteUrl;
    }

    private String getSiteUrl(final SiteConfigPreferences preferences) {
        final String siteUrl = getProperty("siteUrl");
        if (StringUtils.isNotBlank(siteUrl)) {
            log.debug("Found site URL in provider properties, using this as override value: {}", siteUrl);
            return siteUrl;
        }
        final String defaultSiteUrl = preferences.getSiteUrl();
        log.debug("Didn't find site URL in provider properties, using site configuration value: {}", defaultSiteUrl);
        return defaultSiteUrl;
    }

    private static final String PROVIDER_ID = "openid";

    private static OpenIdAuthPlugin INSTANCE;

    private final Properties         _properties;
    private final List<String>       _enabledProviders;
    private final String             _siteUrl;
    private final SerializerService _serializer;

    private       OAuth2RestTemplate _oAuth2RestTemplate;
}
