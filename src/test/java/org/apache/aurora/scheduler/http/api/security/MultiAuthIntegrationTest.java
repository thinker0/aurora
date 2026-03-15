package org.apache.aurora.scheduler.http.api.security;

import org.apache.aurora.scheduler.http.AbstractJettyTest;
import org.junit.Test;
import javax.servlet.http.HttpServletResponse;
import com.sun.jersey.api.client.ClientResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MultiAuthIntegrationTest extends AbstractJettyTest {

  @Test
  public void testOAuth2RedirectWhenNoAuth() throws Exception {
    System.setProperty("http_authentication_mechanism", "OAUTH2");
    System.setProperty("oauth2_issuer_url", "https://keycloak.example.com");
    System.setProperty("oauth2_client_id", "aurora");
    System.setProperty("oauth2_client_secret", "secret");
    System.setProperty("oauth2_jwt_secret", "jwt_secret_key_12345678901234567890");
    System.setProperty("oauth2_redirect_uri", "https://aurora.example.com/oauth2/callback");
    
    replayAndStart();
    
    ClientResponse response = getRequestBuilder("/").get(ClientResponse.class);
    assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
  }

  @Test
  public void testTrustedHeaderWorks() throws Exception {
    System.setProperty("http_authentication_mechanism", "TRUSTED_HEADER");
    
    replayAndStart();
    
    ClientResponse response = getRequestBuilder("/")
        .header("X-Forwarded-User", "admin")
        .get(ClientResponse.class);
        
    assertEquals(HttpServletResponse.SC_OK, response.getStatus());
  }
}