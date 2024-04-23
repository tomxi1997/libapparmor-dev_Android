/usr/local/apache-tomcat-8.0.33/bin/catalina.sh {

  ^/usr/local/jdk1.8.0_92/bin/java {
    network (receive) inet6 stream ip=::ffff:127.0.0.1 port=8080 peer=(ip=::ffff:127.0.0.1 port=52308),

  }
}
