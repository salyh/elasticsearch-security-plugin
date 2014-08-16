package org.elasticsearch.plugins.security.filter;

import java.io.IOException;
import java.io.StringWriter;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class AbstractPermTests {

    @Rule 
    public TestName name = new TestName();
    
    @Rule
    public TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("Starting JUnit-test: " + className + " " + methodName);
        }
    };
    
    protected String loadFile(final String file) throws IOException {

        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
        return sw.toString();

    }
    
    
    static class TestCallback implements UserRoleCallback {

        private final String user;
        private final String role;

        protected TestCallback(final String user, final String role) {
            super();
            this.user = user;
            this.role = role;
        }

        @Override
        public String getRemoteuser() {
            // TODO Auto-generated method stub
            return user;
        }

        @Override
        public boolean isRemoteUserInRole(final String role) {
            // TODO Auto-generated method stub
            return role.equals(this.role);
        }

    }
    
}
