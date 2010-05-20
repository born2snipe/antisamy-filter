package org.wasp;

import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;


public class HttpResponseProxyFactory {
    public HttpServletResponse build(HttpServletResponse response, HttpServletResponseInvocationHandler invocationHandler) {
        return (HttpServletResponse) Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class[]{HttpServletResponse.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        return null;
                    }
                }
        );
    }
}
