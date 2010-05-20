/**
 * Copyright to the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.wasp;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;


public class HttpServletResponseInvocationHandler implements InvocationHandler {
    public final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private final HttpServletResponse delegate;

    public HttpServletResponseInvocationHandler(HttpServletResponse delegate) {
        this.delegate = delegate;
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (name.equals("getWriter")) {
            return new EagerFlushingPrintWriter(output);
        } else if (name.equals("getOutputStream")) {
            return output;
        }
        return method.invoke(delegate, args);
    }

    public String getContents() {
        return new String(output.toByteArray());
    }

    private static class EagerFlushingPrintWriter extends PrintWriter {
        public EagerFlushingPrintWriter(OutputStream out) {
            super(out);
        }

        @Override
        public void write(char cbuf[], int off, int len) {
            super.write(cbuf, off, len);
        }

        public void write(String s, int off, int len) {
            super.write(s, off, len);
            flush();
        }
    }
}
