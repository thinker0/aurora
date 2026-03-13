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
package org.apache.aurora.scheduler.config.validators;

import java.io.File;
import java.io.IOException;

import com.beust.jcommander.ParameterException;
import com.google.common.collect.ImmutableList;

import org.apache.aurora.common.quantity.Amount;
import org.apache.aurora.common.quantity.Data;
import org.apache.aurora.common.quantity.Time;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.fail;

public class ValidatorsTest {

  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  // NotEmptyIterable: empty branch
  @Test(expected = ParameterException.class)
  public void testNotEmptyIterableEmpty() {
    new NotEmptyIterable().validate("param", ImmutableList.of());
  }

  // NotEmptyIterable: non-empty branch (no exception)
  @Test
  public void testNotEmptyIterableNonEmpty() {
    new NotEmptyIterable().validate("param", ImmutableList.of("x"));
  }

  // NotEmptyString: empty branch
  @Test(expected = ParameterException.class)
  public void testNotEmptyStringEmpty() {
    new NotEmptyString().validate("param", "");
  }

  // NotEmptyString: non-empty branch
  @Test
  public void testNotEmptyStringNonEmpty() {
    new NotEmptyString().validate("param", "hello");
  }

  // NotNegativeNumber: negative branch
  @Test(expected = ParameterException.class)
  public void testNotNegativeNumberNegative() {
    new NotNegativeNumber().validate("param", -1);
  }

  // NotNegativeNumber: zero branch (no exception)
  @Test
  public void testNotNegativeNumberZero() {
    new NotNegativeNumber().validate("param", 0);
  }

  // NotNegativeAmount: negative branch
  @Test(expected = ParameterException.class)
  public void testNotNegativeAmountNegative() {
    new NotNegativeAmount().validate("param", Amount.of(-1L, Time.SECONDS));
  }

  // NotNegativeAmount: zero branch (no exception)
  @Test
  public void testNotNegativeAmountZero() {
    new NotNegativeAmount().validate("param", Amount.of(0L, Time.SECONDS));
  }

  // PositiveNumber: zero branch (should throw)
  @Test(expected = ParameterException.class)
  public void testPositiveNumberZero() {
    new PositiveNumber().validate("param", 0);
  }

  // PositiveNumber: positive branch (no exception)
  @Test
  public void testPositiveNumberPositive() {
    new PositiveNumber().validate("param", 1);
  }

  // PositiveAmount: zero branch (should throw)
  @Test(expected = ParameterException.class)
  public void testPositiveAmountZero() {
    new PositiveAmount().validate("param", Amount.of(0L, Data.MB));
  }

  // PositiveAmount: positive branch (no exception)
  @Test
  public void testPositiveAmountPositive() {
    new PositiveAmount().validate("param", Amount.of(1L, Data.MB));
  }

  // ReadableFile: non-readable file branch
  @Test(expected = ParameterException.class)
  public void testReadableFileNotReadable() {
    new ReadableFile().validate("param", new File("/nonexistent/path/file.txt"));
  }

  // ReadableFile: readable file branch (no exception)
  @Test
  public void testReadableFileReadable() throws IOException {
    File f = temporaryFolder.newFile("readable.txt");
    new ReadableFile().validate("param", f);
  }
}
