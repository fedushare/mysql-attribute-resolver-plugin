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
```

## References

* https://www.lsc-group.phys.uwm.edu/wiki/ShibSPAccessControlPluginTutorial
* https://bitbucket.org/PEOFIAMP/shibsp-plugin-attributequery-handler
