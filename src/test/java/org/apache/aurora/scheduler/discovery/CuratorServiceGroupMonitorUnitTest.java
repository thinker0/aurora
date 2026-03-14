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

import org.apache.aurora.scheduler.app.ServiceGroupMonitor.MonitorException;
import org.apache.curator.framework.listen.Listenable;
import org.apache.curator.framework.recipes.cache.CuratorCache;
import org.apache.curator.framework.recipes.cache.CuratorCacheListener;
import org.easymock.EasyMock;
import org.junit.Test;

/**
 * Standalone unit tests for CuratorServiceGroupMonitor that do not require
 * real ZooKeeper infrastructure.
 */
public class CuratorServiceGroupMonitorUnitTest {

  @Test(expected = MonitorException.class)
  @SuppressWarnings("unchecked")
  public void testStartWrapsNonMonitorException() throws Exception {
    // Covers the catch(Exception e) branch in start() that wraps non-MonitorException errors.
    CuratorCache mockCache = EasyMock.createMock(CuratorCache.class);
    Listenable<CuratorCacheListener> listenable = EasyMock.createMock(Listenable.class);
    EasyMock.expect(mockCache.listenable()).andReturn(listenable);
    listenable.addListener(EasyMock.anyObject());
    EasyMock.expectLastCall();
    mockCache.start();
    EasyMock.expectLastCall().andThrow(new RuntimeException("Cache start failed"));
    EasyMock.replay(mockCache, listenable);

    CuratorServiceGroupMonitor monitor =
        new CuratorServiceGroupMonitor(mockCache, name -> name.contains("member_"));
    try {
      monitor.start();
    } finally {
      EasyMock.verify(mockCache, listenable);
    }
  }
}
