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
package org.apache.aurora.scheduler.config.converters;

import com.beust.jcommander.ParameterException;

import org.apache.aurora.common.quantity.Data;
import org.apache.aurora.common.quantity.Time;
import org.apache.aurora.gen.DockerParameter;
import org.apache.aurora.scheduler.config.types.DataAmount;
import org.apache.aurora.scheduler.config.types.TimeAmount;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ConvertersTest {

  // DockerParameterConverter: valid input
  @Test
  public void testDockerParameterConverterValid() {
    DockerParameterConverter converter = new DockerParameterConverter("--docker-param");
    DockerParameter param = converter.convert("name=value");
    assertEquals("name", param.getName());
    assertEquals("value", param.getValue());
  }

  // DockerParameterConverter: no '=' branch
  @Test(expected = ParameterException.class)
  public void testDockerParameterConverterNoEquals() {
    new DockerParameterConverter("--docker-param").convert("noequals");
  }

  // DockerParameterConverter: '=' at position 0 branch
  @Test(expected = ParameterException.class)
  public void testDockerParameterConverterEqualsAtStart() {
    new DockerParameterConverter("--docker-param").convert("=value");
  }

  // DockerParameterConverter: '=' at end branch
  @Test(expected = ParameterException.class)
  public void testDockerParameterConverterEqualsAtEnd() {
    new DockerParameterConverter("--docker-param").convert("name=");
  }

  // TimeAmountConverter: valid input
  @Test
  public void testTimeAmountConverterValid() {
    TimeAmountConverter converter = new TimeAmountConverter("--time");
    TimeAmount amount = converter.convert("5secs");
    assertEquals(new TimeAmount(5, Time.SECONDS), amount);
  }

  // TimeAmountConverter: invalid format (no match) branch
  @Test(expected = ParameterException.class)
  public void testTimeAmountConverterInvalidFormat() {
    new TimeAmountConverter("--time").convert("invalid");
  }

  // TimeAmountConverter: unknown unit branch
  @Test(expected = ParameterException.class)
  public void testTimeAmountConverterUnknownUnit() {
    new TimeAmountConverter("--time").convert("5xyz");
  }

  // DataAmountConverter: valid input
  @Test
  public void testDataAmountConverterValid() {
    DataAmountConverter converter = new DataAmountConverter("--data");
    DataAmount amount = converter.convert("100MB");
    assertEquals(new DataAmount(100, Data.MB), amount);
  }

  // DataAmountConverter: invalid format (no match) branch
  @Test(expected = ParameterException.class)
  public void testDataAmountConverterInvalidFormat() {
    new DataAmountConverter("--data").convert("invalid");
  }

  // DataAmountConverter: unknown unit branch
  @Test(expected = ParameterException.class)
  public void testDataAmountConverterUnknownUnit() {
    new DataAmountConverter("--data").convert("100XB");
  }

  // ClassConverter: valid class name
  @Test
  public void testClassConverterValid() {
    ClassConverter converter = new ClassConverter("--class");
    Class<?> clazz = converter.convert("java.lang.String");
    assertEquals(String.class, clazz);
  }

  // ClassConverter: empty string branch
  @Test(expected = ParameterException.class)
  public void testClassConverterEmpty() {
    new ClassConverter("--class").convert("");
  }

  // ClassConverter: unknown class branch
  @Test(expected = ParameterException.class)
  public void testClassConverterUnknownClass() {
    new ClassConverter("--class").convert("com.nonexistent.Class");
  }

  // ClassConverter: alias branch (KERBEROS5_AUTHN)
  @Test
  public void testClassConverterAlias() {
    ClassConverter converter = new ClassConverter("--class");
    Class<?> clazz = converter.convert("INI_AUTHNZ");
    assertEquals(
        "org.apache.aurora.scheduler.http.api.security.IniShiroRealmModule",
        clazz.getCanonicalName());
  }
}
