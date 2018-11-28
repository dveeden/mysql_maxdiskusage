#include <stdio.h>
#include <sys/statvfs.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <mysql/service_my_plugin_log.h>
#include <mysql/service_security_context.h>

#if MYSQL_VERSION_ID >= 80000
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE  (1)
#endif
#include "sql/sql_error.h"
#else
#include "sql_error.h"
#endif

static uint64_t maxdiskusage_minfree_mb;
static uint64_t maxdiskusage_pct;
static uint64_t maxdiskusage_warn_skip_count;
static uint64_t warn_skipped= 0;
static char *maxdiskusage_monitor_fs= NULL;
static char *maxdiskusage_action= NULL;

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
    uint64_t used_pct;

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
    used_pct = (uint64_t) (100 - (100 * ((double)vfs.f_bavail/(double)vfs.f_blocks)));

    if ((maxdiskusage_pct < 100) && (used_pct >= maxdiskusage_pct))
    {
      if (strncmp(maxdiskusage_action, "WARN", 6) == 0)
      {
        if (warn_skipped >= maxdiskusage_warn_skip_count)
        {
          warn_skipped= 0;
          /* 1642 == ER_SIGNAL_WARN */
          push_warning(thd, Sql_condition::SL_WARNING, 1642,
                       "Writing to a server which has not a lot of free space (Percentage)");
        }
        else
        {
          warn_skipped++;
        }
      }
      else if (strncmp(maxdiskusage_action, "BLOCK", 6) == 0)
      {
        my_plugin_log_message(&plugin, MY_ERROR_LEVEL,
                              "BLOCKING QUERY: Using %lu%%, which is more that %lu%%: %s",
                              used_pct,
                              maxdiskusage_pct,
                              table_access->query.str);
        return TRUE;
      }
      else
      {
        my_plugin_log_message(&plugin, MY_ERROR_LEVEL,
                              "Invalid action set: %s",
                              maxdiskusage_action);
      }
    }

    if ((maxdiskusage_minfree_mb > 0) && (freespace_mb < maxdiskusage_minfree_mb))
    {
      if (strncmp(maxdiskusage_action, "WARN", 6) == 0)
      {
        if (warn_skipped >= maxdiskusage_warn_skip_count)
        {
          warn_skipped= 0;
          /* 1642 == ER_SIGNAL_WARN */
          push_warning(thd, Sql_condition::SL_WARNING, 1642,
                       "Writing to a server which has not a lot of free space (Free Bytes)");
        }
        else
        {
          warn_skipped++;
        }
      }
      else if (strncmp(maxdiskusage_action, "BLOCK", 6) == 0)
      {
        my_plugin_log_message(&plugin, MY_ERROR_LEVEL,
                              "BLOCKING QUERY: Free filesystem space on %s (%lu MB) is less than %lu MB: %s",
                              maxdiskusage_monitor_fs,
                              freespace_mb,
                              maxdiskusage_minfree_mb,
                              table_access->query.str);
        return TRUE;
      }
      else
      {
        my_plugin_log_message(&plugin, MY_ERROR_LEVEL,
                              "Invalid action set: %s",
                              maxdiskusage_action);
      }
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
  warn_skip_count,                                             /* name       */
  maxdiskusage_warn_skip_count,                                /* value      */
  PLUGIN_VAR_OPCMDARG,                                         /* flags      */
  "Skip x events to limit warning rate",                       /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  1000,                                                        /* default    */
  0,                                                           /* minimum    */
  UINT64_MAX,                                                  /* maximum    */
  0                                                            /* blocksize  */
);

static MYSQL_SYSVAR_ULONG(
  pct,                                                         /* name       */
  maxdiskusage_pct,                                            /* value      */
  PLUGIN_VAR_OPCMDARG,                                         /* flags      */
  "Maximum percentage in use",                                 /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  100,                                                         /* default    */
  0,                                                           /* minimum    */
  100,                                                         /* maximum    */
  0                                                            /* blocksize  */
);

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

static MYSQL_SYSVAR_STR(
  action,                                                      /* name       */
  maxdiskusage_action,                                         /* value      */
  PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_MEMALLOC,                   /* flags      */
  "Action to take: BLOCK or WARN",                             /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  "WARN"                                                       /* default    */
);

#if MYSQL_VERSION_ID >= 80000
SYS_VAR *system_variables[] = {
#else
static struct st_mysql_sys_var* system_variables[] = {
#endif
  MYSQL_SYSVAR(warn_skip_count),
  MYSQL_SYSVAR(pct),
  MYSQL_SYSVAR(minfree),
  MYSQL_SYSVAR(monitor_fs),
  MYSQL_SYSVAR(action),
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
#if MYSQL_VERSION_ID >= 80000
  NULL,
#endif
  NULL,                               /* deinit function (when unloaded) */
  0x0006,                             /* version                         */
  NULL,                               /* status variables                */
  system_variables,                   /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;
