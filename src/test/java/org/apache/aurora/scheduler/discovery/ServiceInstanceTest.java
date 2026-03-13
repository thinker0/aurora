/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.aurora.scheduler.discovery;

import com.google.common.collect.ImmutableMap;

import org.apache.aurora.scheduler.discovery.ServiceInstance.Endpoint;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class ServiceInstanceTest {

  private static final Endpoint ENDPOINT_A = new Endpoint("host1", 1000);
  private static final Endpoint ENDPOINT_B = new Endpoint("host2", 2000);

  // ServiceInstance.equals: non-ServiceInstance object (false branch)
  @Test
  public void testServiceInstanceEqualsNonInstance() {
    ServiceInstance instance = new ServiceInstance(ENDPOINT_A, ImmutableMap.of());
    assertNotEquals(instance, "not an instance");
  }

  // ServiceInstance.equals: equal instances (true branch)
  @Test
  public void testServiceInstanceEqualsEqual() {
    ServiceInstance i1 = new ServiceInstance(ENDPOINT_A, ImmutableMap.of("http", ENDPOINT_B));
    ServiceInstance i2 = new ServiceInstance(ENDPOINT_A, ImmutableMap.of("http", ENDPOINT_B));
    assertEquals(i1, i2);
  }

  // ServiceInstance.equals: different serviceEndpoint
  @Test
  public void testServiceInstanceEqualsDifferentEndpoint() {
    ServiceInstance i1 = new ServiceInstance(ENDPOINT_A, ImmutableMap.of());
    ServiceInstance i2 = new ServiceInstance(ENDPOINT_B, ImmutableMap.of());
    assertNotEquals(i1, i2);
  }

  // ServiceInstance.hashCode
  @Test
  public void testServiceInstanceHashCode() {
    ServiceInstance i1 = new ServiceInstance(ENDPOINT_A, ImmutableMap.of());
    ServiceInstance i2 = new ServiceInstance(ENDPOINT_A, ImmutableMap.of());
    assertEquals(i1.hashCode(), i2.hashCode());
  }

  // Endpoint.equals: non-Endpoint object (false branch)
  @Test
  public void testEndpointEqualsNonInstance() {
    assertNotEquals(ENDPOINT_A, "not an endpoint");
  }

  // Endpoint.equals: equal endpoints (true branch)
  @Test
  public void testEndpointEqualsEqual() {
    Endpoint e1 = new Endpoint("host1", 1000);
    Endpoint e2 = new Endpoint("host1", 1000);
    assertEquals(e1, e2);
  }

  // Endpoint.equals: different host
  @Test
  public void testEndpointEqualsDifferentHost() {
    Endpoint e1 = new Endpoint("host1", 1000);
    Endpoint e2 = new Endpoint("host2", 1000);
    assertNotEquals(e1, e2);
  }

  // Endpoint.equals: different port
  @Test
  public void testEndpointEqualsDifferentPort() {
    Endpoint e1 = new Endpoint("host1", 1000);
    Endpoint e2 = new Endpoint("host1", 2000);
    assertNotEquals(e1, e2);
  }

  // Endpoint.hashCode
  @Test
  public void testEndpointHashCode() {
    Endpoint e1 = new Endpoint("host1", 1000);
    Endpoint e2 = new Endpoint("host1", 1000);
    assertEquals(e1.hashCode(), e2.hashCode());
  }

  // ServiceInstance getters
  @Test
  public void testServiceInstanceGetters() {
    ServiceInstance instance = new ServiceInstance(ENDPOINT_A, ImmutableMap.of("http", ENDPOINT_B));
    assertEquals(ENDPOINT_A, instance.getServiceEndpoint());
    assertEquals(ImmutableMap.of("http", ENDPOINT_B), instance.getAdditionalEndpoints());
    assertEquals("ALIVE", instance.getStatus());
  }
}
