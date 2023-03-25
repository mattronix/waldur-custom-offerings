#!/bin/bash

USER=$1
DESKTOP=$2

. .env
mysql="docker exec -it mysql mysql -u ${MYSQL_USER} --password=${MYSQL_PASSWORD} ${MYSQL_DATABASE}"

$mysql -e "insert into guacamole_connection_permission(entity_id, connection_id, permission) values (
	(select entity_id from guacamole_entity where name='${USER}'),
	(select connection_id from guacamole_connection_parameter where parameter_name='hostname' and parameter_value='${DESKTOP}'),
	'READ'
	)";
