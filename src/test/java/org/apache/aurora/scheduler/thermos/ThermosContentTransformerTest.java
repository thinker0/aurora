package org.apache.aurora.scheduler.thermos;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.thermos.ThermosProxyServlet.ThermosContentTransformer;
import org.junit.Before;
import org.junit.Test;

public class ThermosContentTransformerTest extends EasyMockTest {
  @Before
  public void setUp() {

  }

  @Test
  public void testTransformer() throws IOException {
     control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/a/b/c", 1024 * 1024);
    ByteArrayOutputStream buffers = new ByteArrayOutputStream();
    trans.parserAndExchange("<a href='/browser/...'><img src='/img/...'><img src='/img/...'>", buffers);
    assertEquals("<a href='/a/b/c/browser/...'><img src='/a/b/c/img/...'><img src='/a/b/c/img/...'>", buffers.toString());
  }

}
