# ---------------------------------------------------------------------------
# CVE-2021-41773 -- vulnerable Apache HTTP Server 2.4.49
#
# This mirrors vulhub/httpd/CVE-2021-41773/Dockerfile so the experiment is
# self-contained (no git clone needed). If you already cloned Vulhub you may
# simply run theirs:  cd vulhub/httpd/CVE-2021-41773 && docker compose up -d
#
# The two `sed` tweaks are what make the flaw *remotely exploitable*:
#   * mod_cgi / mod_cgid are enabled  -> the traversal can reach /bin/sh
#   * <Directory /> is set to "Require all granted"
#     -> files outside the DocumentRoot are readable instead of being
#        rejected with 403 by the default "Require all denied"
# ---------------------------------------------------------------------------
FROM vulhub/httpd:2.4.49

LABEL maintainer="lab1-secure-api" \
      description="Apache 2.4.49 with CVE-2021-41773 (path traversal / RCE)"

RUN set -ex \
    && sed -i "s|#LoadModule cgid_module modules/mod_cgid.so|LoadModule cgid_module modules/mod_cgid.so|g" /usr/local/apache2/conf/httpd.conf \
    && sed -i "s|#LoadModule cgi_module modules/mod_cgi.so|LoadModule cgi_module modules/mod_cgi.so|g" /usr/local/apache2/conf/httpd.conf \
    && sed -i "s|#Include conf/extra/httpd-autoindex.conf|Include conf/extra/httpd-autoindex.conf|g" /usr/local/apache2/conf/httpd.conf \
    && cat /usr/local/apache2/conf/httpd.conf \
       | tr '\n' '\r' \
       | perl -pe 's|<Directory />.*?</Directory>|<Directory />\n    AllowOverride none\n    Require all granted\n</Directory>|isg' \
       | tr '\r' '\n' \
       | tee /tmp/httpd.conf \
    && mv /tmp/httpd.conf /usr/local/apache2/conf/httpd.conf

EXPOSE 80
