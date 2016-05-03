# mysql-attribute-resolver-plugin

## Build dependencies

* Development tools
  ```Shell
  yum install -y autoconf libtool make gcc gcc-c++
  ```

* Shibboleth SP
  ```Shell
  yum install -y shibboleth-devel liblog4shib-devel
  ```

* MySQL
  ```Shell
  wget http://repo.mysql.com/mysql-community-release-el7-5.noarch.rpm
  rpm -ivh mysql-community-release-el7-5.noarch.rpm

  yum -y install mysql-community-client mysql-community-devel
  ```

## Build steps

```Shell
cd /path/to/mysql-attribute-resolver-plugin
autoreconf -v -i -f
./configure
make
sudo make install
```

## Configuration

* Load the library into `shibd`. Inside the `SPConfig` section of `/etc/shibboleth/shibboleth2.xml`:

    ```xml
    <OutOfProcess>
        <Extensions>
            <Library path="/usr/local/lib/shibboleth/mysqlattributeresolver.so" fatal="true"/>
        </Extensions>
    </OutOfProcess>
    ```

    See the [OutOfProcess element documentation](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPOutOfProcess).

* Add and configure the attribute resolver. In the `ApplicationDefaults` section of `/etc/shibboleth/shibboleth2.xml`:

    ```xml
    <AttributeResolver type="MySQL">
        <Connection host="localhost"
            port="3306"
            username="username"
            password="password"
            dbname="dbname" />
        <Query>
            <![CDATA[
                SELECT * FROM attributes WHERE eppn = $eppn
            ]]>
        </Query>
        <Column name="columnName" attribute="attributeName" />
    </AttributeResolver>
    ```

### Configuration Elements

**Connection**

Specifies database connection and credentials.

Cardinality: exactly one

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| host | string, required | localhost | The database server to connect to |
| port | integer, required | 3306 | The port on the database server to connect to |
| username | string, required | | The username to use to connect to the database |
| password | string, required | | The password to use to connect to the database |
| dbname | string, required | | The name of the MySQL database to connect to |

**Query**

Specifies SQL query. Values of previously resolved attributes can be used as query parameters by placing `$attr`
in the query, where `attr` is the ID of the attribute whose values will be passed as parameters. All parameter
attributes are required to have the same number of values. If the parameter attributes have n values, the query
will be run n times, each time using the nth value of each parameter attribute.

Cardinality: exactly one

**Column**

Define a mapping from a column in the MySQL query result to an attribute.

If the result set of a query contains multiple rows or if multiple result sets are created by running the query
more than once, the attributes will be populated with multiple values. If a row contains a null value for a column,
no value will be added to the attribute for that row. If all rows in all result sets contain null values for a
common, the attribute mapped from that column will not be resolved.

Cardinality: one or more

Attributes:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| name | string, required | | The name of the column in the query result set |
| attribute | string, required | | The name of the attribute to populate |

## References

* https://www.lsc-group.phys.uwm.edu/wiki/ShibSPAccessControlPluginTutorial
* https://bitbucket.org/PEOFIAMP/shibsp-plugin-attributequery-handler
* https://dev.mysql.com/doc/refman/5.7/en/c-api-building-clients.html
* https://dev.mysql.com/doc/ndbapi/en/ndb-start-autotools.html
