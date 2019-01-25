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

import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.security.XDATUser;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * OIDC user details
 * 
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 * 
 */
public class OpenIdConnectUserDetails extends XDATUser {
	public OpenIdConnectUserDetails(final Map<String, String> userInfo, final OAuth2AccessToken token, final OpenIdAuthPlugin plugin) {
		this.setUsername(providerId + "_" + userInfo.get("sub"));
		this.token = token;
		this.plugin = plugin;
		this.email = getUserInfo(userInfo, "emailProperty");
		this.setFirstname(getUserInfo(userInfo, "givenNameProperty"));
		this.setLastname(getUserInfo(userInfo, "familyNameProperty"));
		this.name = userInfo.get("name");
		this.picture = userInfo.get("picture");
	}

	private String getUserInfo(final Map<String, String> userInfo, final String property) {
		return StringUtils.defaultIfBlank(userInfo.get(plugin.getProperty(property)), "");
	}

	public OAuth2AccessToken getToken() {
		return token;
	}

	public void setToken(OAuth2AccessToken token) {
		this.token = token;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getUsername() {
		return username;
	}

	public String getFirstname() {
		return firstName;
	}

	public String getLastname() {
		return lastName;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String e) {
		this.email = e;
	}

	public void setFirstname(String firstname) {
		this.firstName = firstname;
	}

	public void setLastname(String lastname) {
		this.lastName = lastname;
	}

	private OAuth2AccessToken   token;
	private String              email;
	private Map<String, String> _userInfo;
	private String              name;
	private String              picture;
	private String              firstName;
	private String              lastName;
	private String              pw;
	private String              username;
	private String              providerId;
	private OpenIdAuthPlugin    plugin;
}
