package com.example.login_test;

import org.apache.catalina.Context;
import org.apache.catalina.session.StandardManager;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TomcatConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatCustomizer() {
        return factory -> factory.addContextCustomizers((TomcatContextCustomizer) context -> {
            StandardManager manager = new StandardManager();
            manager.setMaxActiveSessions(-1); // 세션 캐싱 방지
            context.setManager(manager);
        });
    }
}
