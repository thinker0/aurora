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
package org.apache.aurora.scheduler.thermos;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.thermos.ThermosProxyServlet.ThermosContentTransformer;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ThermosContentTransformerTest extends EasyMockTest {

  @Test
  public void testTransformer() throws IOException {
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/a/b/c", 1024 * 1024);
    ByteArrayOutputStream buffers = new ByteArrayOutputStream();
    trans.parserAndExchange("<a href='/browser/...'><img src='/img/...'><img src='/img/...'>",
        buffers);
    assertEquals("<a href='/a/b/c/browser/...'><img src='/a/b/c/img/...'>"
            + "<img src='/a/b/c/img/...'>", buffers.toString("UTF-8"));
  }

  @Test
  public void testNoMatchingPatterns() throws IOException {
    // Covers the path where no key bytes are found — pos++ without entering the key-byte block.
    // Also covers final "if (pos > start)" flush at end of method.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/a/b/c", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("no matching patterns here", out);
    assertEquals("no matching patterns here", out.toString("UTF-8"));
  }

  @Test
  public void testEmptyInput() throws IOException {
    // Covers the empty-input edge case — while loop body never executes, final flush skipped.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/a/b/c", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("", out);
    assertEquals("", out.toString("UTF-8"));
  }

  @Test
  public void testDoubleQuoteHrefReplacement() throws IOException {
    // Covers href="/ replacement (double-quote variant).
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("<a href=\"/path/to/page\">click</a>", out);
    assertEquals("<a href=\"/prefix/path/to/page\">click</a>", out.toString("UTF-8"));
  }

  @Test
  public void testSrcDoubleQuoteReplacement() throws IOException {
    // Covers src="/ replacement.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("<img src=\"/image.png\">", out);
    assertEquals("<img src=\"/prefix/image.png\">", out.toString("UTF-8"));
  }

  @Test
  public void testVarUrlReplacement() throws IOException {
    // Covers "var url = "/" replacement.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("var url = \"/api/data\"", out);
    assertEquals("var url = \"/prefix/api/data\"", out.toString("UTF-8"));
  }

  @Test
  public void testDataUrlReplacement() throws IOException {
    // Covers data-url="/ and data-url="m replacements.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("data-url=\"/path\" data-url=\"metric\"", out);
    assertEquals("data-url=\"/prefix/path\" data-url=\"/prefix/metric\"",
        out.toString("UTF-8"));
  }

  @Test
  public void testPartialKeyByteNoMatch() throws IOException {
    // A key byte appears but the full pattern doesn't match — covers the match=false break path.
    // 'h' is a key byte (from href="/ etc), but "hello" doesn't match any replacement key.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    trans.parserAndExchange("hello world", out);
    assertEquals("hello world", out.toString("UTF-8"));
  }

  @Test
  public void testKeyByteAtEndOfBuffer() throws IOException {
    // Key byte right at the end — fromLen > read - pos, so the pattern-length check fails.
    // 'h' is a key byte, put it at position where remaining bytes < any pattern length.
    control.replay();
    ThermosContentTransformer trans = new ThermosContentTransformer("/prefix", 1024 * 1024);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Just 'h' alone — too short to match any pattern starting with 'h'.
    trans.parserAndExchange("h", out);
    assertEquals("h", out.toString("UTF-8"));
  }

}
