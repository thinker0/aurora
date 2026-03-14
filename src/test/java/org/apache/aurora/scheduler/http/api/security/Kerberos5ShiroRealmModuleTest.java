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
package org.apache.aurora.scheduler.http.api.security;

import java.io.File;
import java.security.Provider;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.kerberos.KerberosPrincipal;

import com.google.inject.Guice;
import com.google.inject.Module;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertTrue;

public class Kerberos5ShiroRealmModuleTest extends EasyMockTest {
  private static final KerberosPrincipal SERVER_PRINCIPAL =
      new KerberosPrincipal("HTTP/aurora.example.com@EXAMPLE.COM");

  private File serverKeytab;
  private GSSCredential gssCredential;
  private AtomicBoolean createCredentialCalled;

  private Module module;

  @Before
  public void setUp() {
    serverKeytab = createMock(File.class);
    gssCredential = createMock(GSSCredential.class);
    createCredentialCalled = new AtomicBoolean(false);

    // GSSManager is an abstract JDK class in a restricted module (java.security.jgss).
    // EasyMock 5.x + ByteBuddy cannot proxy JDK classes in restricted modules via VarHandle.
    // Use a concrete anonymous subclass instead.
    GSSManager gssManager = new GSSManager() {
      @Override
      public Oid[] getMechs() {
        throw new UnsupportedOperationException();
      }

      @Override
      public Oid[] getNamesForMech(Oid mech) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public Oid[] getMechsForName(Oid nameType) {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSName createName(String nameStr, Oid nameType) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSName createName(String nameStr, Oid nameType, Oid mech) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSName createName(byte[] name, Oid nameType) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSName createName(byte[] name, Oid nameType, Oid mech) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSCredential createCredential(int usage) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSCredential createCredential(GSSName aName, int lifetime, Oid mech, int usage)
          throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSCredential createCredential(GSSName aName, int lifetime, Oid[] mechs, int usage)
          throws GSSException {
        createCredentialCalled.set(true);
        return gssCredential;
      }

      @Override
      public GSSContext createContext(
          GSSName peer, Oid mech, GSSCredential myCred, int lifetime) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSContext createContext(GSSCredential myCred) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public GSSContext createContext(byte[] interProcessToken) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public void addProviderAtFront(Provider p, Oid mech) throws GSSException {
        throw new UnsupportedOperationException();
      }

      @Override
      public void addProviderAtEnd(Provider p, Oid mech) throws GSSException {
        throw new UnsupportedOperationException();
      }
    };

    module = new Kerberos5ShiroRealmModule(serverKeytab, SERVER_PRINCIPAL, gssManager);
  }

  @Test
  public void testConfigure() throws Exception {
    expect(serverKeytab.getAbsolutePath()).andReturn("path.keytab");

    control.replay();

    Guice.createInjector(module).getInstance(Kerberos5Realm.class);
    assertTrue("createCredential was not called during Kerberos5Realm initialization",
        createCredentialCalled.get());
  }
}
