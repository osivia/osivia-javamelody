Ajouter ces lignes dans le fichier portal-server.war/web.xml pour activer Java Melody : 
 
<filter>
    <filter-name>monitoring</filter-name>
    <filter-class>net.bull.javamelody.AdaptedMonitoringFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>monitoring</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
<listener>
    <listener-class>net.bull.javamelody.SessionListener</listener-class>
</listener>