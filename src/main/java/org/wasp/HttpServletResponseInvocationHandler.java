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
