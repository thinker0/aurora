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
package org.apache.aurora.scheduler.http;

import java.util.Optional;

import javax.ws.rs.core.Response;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.gen.Resource;
import org.apache.aurora.gen.ResourceAggregate;
import org.apache.aurora.scheduler.storage.QuotaStore;
import org.apache.aurora.scheduler.storage.Storage;
import org.apache.aurora.scheduler.storage.Storage.StoreProvider;
import org.apache.aurora.scheduler.storage.entities.IResourceAggregate;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;

public class QuotasTest extends EasyMockTest {

  private Storage storage;
  private StoreProvider storeProvider;
  private QuotaStore quotaStore;
  private Quotas quotas;

  private static IResourceAggregate makeAggregate(double cpus, long ramMb, long diskMb) {
    ResourceAggregate agg = new ResourceAggregate();
    agg.setResources(ImmutableSet.of(
        Resource.numCpus(cpus),
        Resource.ramMb(ramMb),
        Resource.diskMb(diskMb)));
    return IResourceAggregate.build(agg);
  }

  @Before
  public void setUp() {
    storage = createMock(Storage.class);
    storeProvider = createMock(StoreProvider.class);
    quotaStore = createMock(QuotaStore.class);
    quotas = new Quotas(storage);
  }

  @SuppressWarnings("unchecked")
  private void expectRead() {
    Capture<Storage.Work<Object, RuntimeException>> work = EasyMock.newCapture();
    expect(storage.<Object, RuntimeException>read(capture(work)))
        .andAnswer(() -> work.getValue().apply(storeProvider));
  }

  @Test
  public void testGetQuotasAllRoles() {
    IResourceAggregate aggregate = makeAggregate(2.0, 1024L, 2048L);
    expectRead();
    expect(storeProvider.getQuotaStore()).andReturn(quotaStore);
    expect(quotaStore.fetchQuotas()).andReturn(ImmutableMap.of("role1", aggregate));

    control.replay();

    Response response = quotas.getQuotas(null);
    assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
  }

  @Test
  public void testGetQuotaByRoleFound() {
    IResourceAggregate aggregate = makeAggregate(1.0, 512L, 1024L);
    expectRead();
    expect(storeProvider.getQuotaStore()).andReturn(quotaStore);
    expect(quotaStore.fetchQuota("roleX")).andReturn(Optional.of(aggregate));

    control.replay();

    Response response = quotas.getQuotas("roleX");
    assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
  }

  @Test
  public void testGetQuotaByRoleNotFound() {
    expectRead();
    expect(storeProvider.getQuotaStore()).andReturn(quotaStore);
    expect(quotaStore.fetchQuota("noRole")).andReturn(Optional.empty());

    control.replay();

    Response response = quotas.getQuotas("noRole");
    assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
  }
}
