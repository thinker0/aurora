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
package org.apache.aurora.scheduler.storage.backup;

import java.io.File;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.storage.Snapshotter;
import org.apache.aurora.scheduler.storage.durability.Persistence.PersistenceException;
import org.junit.Before;
import org.junit.Test;

public class BackupReaderTest extends EasyMockTest {

  private Snapshotter snapshotter;

  @Before
  public void setUp() {
    snapshotter = createMock(Snapshotter.class);
  }

  // BackupReader.recover: file does not exist branch
  @Test(expected = PersistenceException.class)
  public void testRecoverFileNotExists() throws PersistenceException {
    File nonExistent = new File("/nonexistent/backup/file.bak");
    BackupReader reader = new BackupReader(nonExistent, snapshotter);

    control.replay();

    reader.recover();
  }

  // BackupReader.persist: always throws UnsupportedOperationException
  @Test(expected = UnsupportedOperationException.class)
  public void testPersistThrows() {
    File file = new File("/some/path");
    BackupReader reader = new BackupReader(file, snapshotter);

    control.replay();

    reader.persist(null);
  }

  // BackupReader.prepare: no-op
  @Test
  public void testPrepareNoOp() {
    File file = new File("/some/path");
    BackupReader reader = new BackupReader(file, snapshotter);

    control.replay();

    reader.prepare();
  }
}
