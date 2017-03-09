#include <stdio.h>
#include <sys/statvfs.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <mysql/service_my_plugin_log.h>
#include <mysql/service_security_context.h>

static uint64_t maxdiskusage_minfree_mb;
static char *maxdiskusage_monitor_fs= NULL;

static MYSQL_PLUGIN plugin= NULL;

static bool is_super(MYSQL_THD thd)
{
  MYSQL_SECURITY_CONTEXT ctx;
  my_svc_bool is_super= FALSE;

  /* setting panic mode requires super */
  return (
    thd != NULL &&
    !thd_get_security_context(thd, &ctx) &&
    !security_context_get_option(ctx, "privilege_super", &is_super) &&
    is_super);
}


static int
maxdiskusage_notify(MYSQL_THD thd,
                      mysql_event_class_t event_class,
                      const void *event)
{
  struct statvfs vfs;

  /* Always allow super */
  if (is_super(thd))
    return FALSE;

  if (event_class == MYSQL_AUDIT_TABLE_ACCESS_CLASS)
  {
    const struct mysql_event_table_access *table_access=
      (const struct mysql_event_table_access *)event;
    uint64_t freespace_mb;

    /* Always allow DELETE, TRUNCATE, SELECT */
    switch (table_access->sql_command_id) {
      case SQLCOM_DELETE:
      case SQLCOM_DELETE_MULTI:
      case SQLCOM_TRUNCATE:
      case SQLCOM_SELECT:
        return FALSE;
      default: ;
    }

    /* TODO: replace / with @@datadir */
    if (statvfs(maxdiskusage_monitor_fs, &vfs) != 0)
      return TRUE;

    freespace_mb = (vfs.f_bsize * vfs.f_bavail) / 1024 / 1024;

    if (freespace_mb < maxdiskusage_minfree_mb)
    {
      my_plugin_log_message(&plugin, MY_ERROR_LEVEL,
                            "BLOCKING QUERY: Free filesystem space on %s (%lu MB) is less than %lu MB: %s",
                            maxdiskusage_monitor_fs,
                            freespace_mb,
                            maxdiskusage_minfree_mb,
                            table_access->query.str);
      return TRUE;
    }
    
  }

  return FALSE;
}


static struct st_mysql_audit maxdiskusage_descriptor=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
  NULL,                                             /* release_thd function */
  maxdiskusage_notify,                              /* notify function      */
  {
    0,                                              /* general */
    0,                                              /* connection */
    0,                                              /* parse */
    0,                                              /* authorization */
    MYSQL_AUDIT_TABLE_ACCESS_ALL,                   /* table access */
    0,                                              /* global variables */
    0,                                              /* server startup */
    0,                                              /* server shutdown */
    0,                                              /* command */
    0,                                              /* query */
    0                                               /* stored program */
  }
};

/* plumbing */

static MYSQL_SYSVAR_ULONG(
  minfree,                                                     /* name       */
  maxdiskusage_minfree_mb,                                     /* value      */
  PLUGIN_VAR_OPCMDARG,                                         /* flags      */
  "Minimum free disk space",                                   /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  0,                                                           /* default    */
  0,                                                           /* minimum    */
  UINT64_MAX,                                                  /* maximum    */
  0                                                            /* blocksize  */
);

static MYSQL_SYSVAR_STR(
  monitor_fs,                                                  /* name       */
  maxdiskusage_monitor_fs,                                     /* value      */
  PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_MEMALLOC,                   /* flags      */
  "Filesystem to test for disk usage",                         /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  "/var/lib/mysql"                                             /* default    */
);

static struct st_mysql_sys_var* system_variables[] = {
  MYSQL_SYSVAR(minfree),
  MYSQL_SYSVAR(monitor_fs),
  NULL
};


static int maxdiskusage_init(MYSQL_PLUGIN p)
{
  plugin= p;
  return 0;
}

/** Plugin declaration */

mysql_declare_plugin(maxdiskusage)
{
  MYSQL_AUDIT_PLUGIN,                 /* type                            */
  &maxdiskusage_descriptor,           /* descriptor                      */
  "maxdiskusage",                     /* name                            */
  "Daniël van Eeden",                 /* author                          */
  "Better handle high diskusage",     /* description                     */
  PLUGIN_LICENSE_GPL,
  maxdiskusage_init,                  /* init function (when loaded)     */
  NULL,                               /* deinit function (when unloaded) */
  0x0003,                             /* version                         */
  NULL,                               /* status variables                */
  system_variables,                   /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;
