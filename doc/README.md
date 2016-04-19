# mysql-attribute-resolver-plugin

## Build dependencies

```Shell
yum install -y autoconf libtool make gcc gcc-c++
yum install -y shibboleth-devel liblog4shib-devel
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

In `/etc/shibboleth/shibboleth2.xml`

Inside `SPConfig` section:

```xml
<OutOfProcess>
    <Extensions>
        <Library path="/usr/local/lib/shibboleth/mysqlattributeresolver.so" fatal="true"/>
    </Extensions>
</OutOfProcess>
```

In `ApplicationDefaults` section:

```xml
<AttributeResolver type="MySQL">
    <Connection host="localhost"
        port="3306"
        username="username"
        password="password"
        dbname="dbname" />
    <Query>
        <![CDATA[
            SELECT ...
        ]]>
    </Query>
    <Column name="columnName" attribute="attributeName" />
</AttributeResolver>
```

## References

* https://www.lsc-group.phys.uwm.edu/wiki/ShibSPAccessControlPluginTutorial
* https://bitbucket.org/PEOFIAMP/shibsp-plugin-attributequery-handler
