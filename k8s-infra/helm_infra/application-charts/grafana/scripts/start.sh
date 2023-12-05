#!/bin/bash

echo $GF_PATHS_HOME

MAIN_DIR=$(dirname $GF_PATHS_HOME)

echo $MAIN_DIR

cp -r /usr/share/grafana/ ${MAIN_DIR}/.

cp -Lr /icons/* ${GF_PATHS_HOME}/public/img/.


sed -i -e 's#<footer#<!--<footer#' ${GF_PATHS_HOME}/public/views/index.html
sed -i -e 's#\/footer>#\/footer>-->#' ${GF_PATHS_HOME}/public/views/index.html
sed -i -e 's#<title>Grafana</title>#<title>Cisco VIM Monitor</title>#' ${GF_PATHS_HOME}/public/views/index.html
sed -i -e 's#Loading Grafana#Loading Cisco VIM Monitor#' ${GF_PATHS_HOME}/public/views/index.html

sed -i -e 's#" - Grafana":"Grafana"#" - Cisco VIM Monitor":"Cisco VIM Monitor"#' ${GF_PATHS_HOME}/public/build/app.*.js
sed -i -e 's#windowTitlePrefix:"Grafana - "#windowTitlePrefix:"Cisco VIM Monitor - "#' ${GF_PATHS_HOME}/public/build/app.*.js
sed -i -e 's#className:t,src:"public/img/grafana_icon.svg"#className:t,src:"public/img/grafana_com_auth_icon.svg"#g' ${GF_PATHS_HOME}/public/build/app.*.js
sed -i -e 's#AppTitle="Grafana"#AppTitle="Cisco VIM Monitor"#g' ${GF_PATHS_HOME}/public/build/app.*.js
sed -i -e 's#displayForgotPassword:.*onSubmit:s#displayForgotPassword:!1,onSubmit:s#' ${GF_PATHS_HOME}/public/build/app.*.js

sed -i -e 's#Grafana#Cisco VIM Monitor#' ${GF_PATHS_HOME}/public/build/DashboardPage.*.js
sed -i -e 's#i||u#1#' ${GF_PATHS_HOME}/public/build/48.*.js
sed -i -e 's#when ldap or auth proxy authentication is enabled.##' ${GF_PATHS_HOME}/public/build/48.*.js

sed -i -e 's#logo-wordmark{[^}]*}#logo-wordmark{}#g' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's#e45602#059fd9#' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's#bc3e06#059fd9#g' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's/\#f60/\#059fd9/g' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's#logo-icon{width:130px}#logo-icon{width:200px}#' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's/opacity:.6;background:\#000;color:\#fbfbfb/opacity:1;background:#fff;color:#000000/' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's#.app-grafana .logo-wordmark{background:url(../img/grafana_typelogo.svg) top no-repeat;#.app-grafana .logo-wordmark{display:none;#' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css
sed -i -e 's#.login-page .footer{display:block;#.login-page .footer{display:none;#' ${GF_PATHS_HOME}/public/build/grafana.dark.*.css

exec /run.sh
