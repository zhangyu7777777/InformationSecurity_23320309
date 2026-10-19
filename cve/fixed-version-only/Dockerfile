# Same permissive configuration as the vulnerable Vulhub image, but with the
# patched Apache version. This isolates the effect of the version upgrade.
FROM httpd:2.4.51

RUN set -ex \
    && sed -i "s|#LoadModule cgid_module modules/mod_cgid.so|LoadModule cgid_module modules/mod_cgid.so|g" /usr/local/apache2/conf/httpd.conf \
    && sed -i "s|#LoadModule cgi_module modules/mod_cgi.so|LoadModule cgi_module modules/mod_cgi.so|g" /usr/local/apache2/conf/httpd.conf \
    && sed -i "s|#Include conf/extra/httpd-autoindex.conf|Include conf/extra/httpd-autoindex.conf|g" /usr/local/apache2/conf/httpd.conf \
    && sed -i "s|Require all denied|Require all granted|g" /usr/local/apache2/conf/httpd.conf
