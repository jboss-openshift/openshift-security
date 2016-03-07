/**
 *  Copyright 2016 Red Hat, Inc.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package org.openshift.security.web.rule;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class RuleFilter implements Filter {

    private final List<Rule> rules = new ArrayList<Rule>();
    private String source;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String source = filterConfig.getInitParameter("properties");
        if (source != null) {
            InputStream stream = filterConfig.getServletContext().getResourceAsStream(source);
            if (stream == null) {
                throw new ServletException("properties not found at " + source);
            } else {
                Properties properties = new Properties();
                try {
                    properties.load(stream);
                } catch (IOException ioe) {
                    throw new ServletException("problem loading properties from " + source, ioe);
                }
                init(source, properties);
            }
        }
    }

    // package-protected for junit testing
    void init(String source, Properties properties) {
        this.source = source;
        for (Object key : properties.keySet()) {
            String name = (String)key;
            String config = properties.getProperty(name);
            if (config != null) {
                rules.add(new Rule(name, config));
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        RuleData data = new ServletRuleData(request, response);
        if (doFilter(data)) {
            chain.doFilter(request, response);
        }
    }

    // package-protected for junit testing
    boolean doFilter(RuleData data) throws IOException {
        for (Rule rule : rules) {
            if (!rule.accepts(data)) {
                String error = "forbidden by " + rule.getName() + " rule";
                String log = data.getPath() + " " + error + " in " + source + ": " + rule;
                data.log(log);
                data.sendError(HttpServletResponse.SC_FORBIDDEN, error);
                return false;
            }
        }
        return true;
    }

    @Override
    public void destroy() {
        rules.clear();
        source = null;
    }

}
