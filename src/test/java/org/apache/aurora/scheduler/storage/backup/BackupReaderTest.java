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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.stream.Stream;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.gen.storage.Snapshot;
import org.apache.aurora.scheduler.storage.Snapshotter;
import org.apache.aurora.scheduler.storage.durability.Persistence;
import org.apache.aurora.scheduler.storage.durability.Persistence.PersistenceException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TIOStreamTransport;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertNotNull;

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

  // BackupReader.recover: file exists — covers the true branch of backupFile.exists()
  @Test
  public void testRecoverFileExists() throws Exception {
    File backupFile = Files.createTempFile("backup-test", ".bak").toFile();
    backupFile.deleteOnExit();

    // Write a valid empty Thrift Snapshot to the file.
    Snapshot snapshot = new Snapshot();
    try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(backupFile))) {
      TBinaryProtocol protocol = new TBinaryProtocol(new TIOStreamTransport(out));
      snapshot.write(protocol);
    }

    expect(snapshotter.asStream(org.easymock.EasyMock.anyObject()))
        .andReturn(Stream.empty());

    control.replay();

    BackupReader reader = new BackupReader(backupFile, snapshotter);
    Stream<Persistence.Edit> result = reader.recover();
    assertNotNull(result);
  }
}
