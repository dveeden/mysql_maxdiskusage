# Usage
```
mysql> INSTALL PLUGIN maxdiskusage SONAME 'maxdiskusage.so';
mysql> SET GLOBAL maxdiskusage_minfree=1000;
mysql> SET GLOBAL maxdiskusage_monitor_fs='/var/lib/mysql';
mysql> SET GLOBAL maxdiskusage_action='WARN';
```

With WARN:
```
mysql> INSERT INTO t1() VALUES();
Query OK, 1 row affected, 1 warning (0.00 sec)

mysql> SHOW WARNINGS;
+---------+------+------------------------------------------+
| Level   | Code | Message                                  |
+---------+------+------------------------------------------+
| Warning | 1642 | Writing to a server with high disk usage |
+---------+------+------------------------------------------+
1 row in set (0.00 sec)
```

With BLOCK:
```
mysql> INSERT INTO t1() VALUES();
ERROR 3164 (HY000): Aborted by Audit API ('MYSQL_AUDIT_TABLE_ACCESS_INSERT';1).
```

This message is also written to the error log:
```
2018-02-21T08:55:10.490978Z 12 [ERROR] Plugin maxdiskusage reported: 'BLOCKING QUERY: Free filesystem space on /home (7682 MB) is less than 10000 MB: INSERT INTO t1() VALUES()'
```

# Settings

| Setting                        | Default        | Description                                      |
|--------------------------------|----------------|--------------------------------------------------|
| `maxdiskusage_action`          | WARN           | WARN or BLOCK                                    |
| `maxdiskusage_note`            | ''             | Note to add to the warning message               |
| `maxdiskusage_minfree`         | 0              | Act if less than x MB of free space is available |
| `maxdiskusage_monitor_fs`      | /var/lib/mysql | Directory to monitor, usally @@datadir           |
| `maxdiskusage_pct`             | 100            | Warn if over this percentage of usage            |
| `maxdiskusage_warn_skip_count` | 1000           | Skip every x events, reduces warning rate        |

These can be set with SET GLOBAL, but you probably want to put those in your my.cnf

# Building

This is tested against MySQL 5.7 and MySQL 8.0. Pull requests for other MySQL and MariaDB
versions are welcome.

Copy the `mysql_maxdiskusage` directory to the `plugin` directory of the MySQL source code.
Build the code as usual or just run `make maxdiskusag`.
Either use the resulting build or copy `maxdiskusage.so` to the `plugin_dir`.

https://dev.mysql.com/doc/refman/5.7/en/compiling-plugin-libraries.html

Might contain some code from https://github.com/gkodinov/audit_tripwire

# Related links

* http://databaseblog.myname.nl/2017/03/improving-mysql-out-of-disk-space.html
