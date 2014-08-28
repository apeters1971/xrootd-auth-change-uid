/************************************************************************
 * XRootD Change FS Uid                                                 *
 * Copyright © 2013 CERN/Switzerland                                    *
 *                                                                      *
 * Author: Joaquim Rocha <joaquim.rocha@cern.ch>                        *
 *                                                                      *
 * This program is free software: you can redistribute it and/or modify *
 * it under the terms of the GNU General Public License as published by *
 * the Free Software Foundation, either version 3 of the License, or    *
 * (at your option) any later version.                                  *
 *                                                                      *
 * This program is distributed in the hope that it will be useful,      *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 * GNU General Public License for more details.                         *
 *                                                                      *
 * You should have received a copy of the GNU General Public License    *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.*
 ************************************************************************/

#include <dlfcn.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/fsuid.h>
#include <XrdOuc/XrdOucTrace.hh>
#include <XrdOuc/XrdOucEnv.hh>
#include <XrdOuc/XrdOucStream.hh>
#include <XrdSys/XrdSysError.hh>
#include "AuthChangeFsUid.hh"

#define CACHE_LIFE_TIME (60 * 5) // seconds

XrdSysError TkEroute(0, "AuthChangeFsUid");
XrdOucTrace TkTrace(&TkEroute);

XrdVERSIONINFO(XrdAccAuthorizeObject, AuthChangeFsUid);

extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger *lp,
                                                     const char   *cfn,
                                                     const char   *parm,
                                                     XrdVersionInfo &vInfo);

void
AuthChangeFsUid::updateUidCache(const std::string &name)
{
  struct passwd *pass;
  struct passwd passwdinfo;
  memset(&passwdinfo, 0, sizeof(struct passwd));
  char namebuffer[16384];

  UidAndTimeStamp *uidAndTime = 0;

  {
    XrdSysMutexHelper mutexHelper(mMutex);

    if (mNameUid.count(name) == 0)
    {
      UidAndTimeStamp stamp = {0, 0};
      uidAndTime = &stamp;
    }
    else
      uidAndTime = &mNameUid[name];
  }

  if (!getpwnam_r(name.c_str(), &passwdinfo,
                  namebuffer, sizeof(namebuffer), &pass) && pass)
  {
    XrdSysMutexHelper mutexHelper(mMutex);
    uidAndTime->uid = pass->pw_uid;
    uidAndTime->gid = pass->pw_gid;
    uidAndTime->lastUpdate = time(NULL);
    mNameUid[name] = *uidAndTime;
  }
  else
  {
    TkEroute.Say("------ AuthChangeFsUid: [ERROR] getwpnam_r failed for "
                 "user=",name.c_str());
    uidAndTime->uid = 99;
    uidAndTime->gid = 99;
    uidAndTime->lastUpdate = time(NULL);
    mNameUid[name] = *uidAndTime;
  }
}

void
AuthChangeFsUid::getUidAndGid(const std::string &name, uid_t &uid, gid_t &gid)
{
  bool updateCache = true;

  {
    XrdSysMutexHelper mutexHelper(mMutex);

    if (mNameUid.count(name) > 0)
    {
      time_t lastUpdate = mNameUid[name].lastUpdate;
      time_t currentTime = time(NULL);

      updateCache = difftime(currentTime, lastUpdate) > CACHE_LIFE_TIME;
    }
  }

  if (updateCache)
  {
    TkEroute.Say("------ AuthChangeFsUid: Updating uids cache...");
    updateUidCache(name);
  }

  {
    XrdSysMutexHelper mutexHelper(mMutex);

    uid = mNameUid[name].uid;
    gid = mNameUid[name].gid;
  }
}

const char *
AuthChangeFsUid::getDelegateAuthLibPath(const char *config)
{
  XrdOucStream Config;
  int cfgFD;
  char *var, *libPath = 0;

  if ((cfgFD = open(config, O_RDONLY, 0)) < 0)
    return 0;

  Config.Attach(cfgFD);
  while ((var = Config.GetMyFirstWord()))
  {
    if (strcmp(var, "authchangefsuid.authlib") == 0)
    {
      var += 14;
      libPath = Config.GetWord();
      break;
    }
  }

  Config.Close();

  return libPath;
}

void
AuthChangeFsUid::loadDelegateAuthLib(const char *libPath)
{
  if (libPath && (!strcmp(libPath,"default")))
  {
    mDelegateAuthLib = XrdAccDefaultAuthorizeObject(mLogger, mConfig, mParam,
                                      XrdVERSIONINFOVAR(XrdAccAuthorizeObject));
    return;
  }

  mDelegateAuthLibHandle = dlopen(libPath, RTLD_NOW);

  if (mDelegateAuthLibHandle == 0)
  {
    TkEroute.Say("------ AuthChangeFsUid: Could not open auth lib ",
                 libPath);
    return;
  }

  mAuthObjHandler = (GetAuthObject_t) dlsym(mDelegateAuthLibHandle,
                                           "XrdAccAuthorizeObject");

  if (mAuthObjHandler == 0)
  {
    TkEroute.Say("------ AuthChangeFsUid: Could not symbol for "
                 "XrdAccAuthorizeObject in ", libPath);

    dlclose(mDelegateAuthLibHandle);
    mDelegateAuthLibHandle = 0;
    return;
  }

  mDelegateAuthLib = (*mAuthObjHandler)(mLogger, mConfig, mParam);
}

AuthChangeFsUid::AuthChangeFsUid(XrdSysLogger *logger,
                                 const char   *config,
                                 const char   *param)
  : mLogger(logger),
    mConfig(config),
    mParam(param),
    mDelegateAuthLibHandle(0),
    mAuthObjHandler(0),
    mDelegateAuthLib(0)
{
  const char *delegateAuthLibPath = getDelegateAuthLibPath(mConfig);

  seteuid(0);
  setegid(0);

  if (delegateAuthLibPath)
    loadDelegateAuthLib(delegateAuthLibPath);
}

AuthChangeFsUid::~AuthChangeFsUid()
{
  delete mDelegateAuthLib;
  mDelegateAuthLib = 0;

  if (mDelegateAuthLibHandle)
  {
    dlclose(mDelegateAuthLibHandle);
    mDelegateAuthLibHandle = 0;
  }
}

XrdAccPrivs
AuthChangeFsUid::Access(const XrdSecEntity    *entity,
                        const char            *path,
                        const Access_Operation oper,
                        XrdOucEnv             *env)
{
  uid_t uid;
  gid_t gid;

  getUidAndGid(entity->name?entity->name:"nobody", uid, gid);

  TkEroute.Say("------ AuthChangeFsUid: Setting FS uid from user=",
               entity->name?entity->name:"nobody");

  setfsuid(uid);
  setfsgid(gid);

  if (env) {
    env->PutInt("uid", uid);
    env->PutInt("gid", gid);
  }

  if (mDelegateAuthLib == 0)
    return XrdAccPriv_All;

  return mDelegateAuthLib->Access(entity, path, oper, env);
}

extern "C" XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                                  const char   *cfn,
                                                  const char   *parm)
{
  TkEroute.SetPrefix("access_auth_fsuid_");
  TkEroute.logger(lp);

  AuthChangeFsUid *authlib = new AuthChangeFsUid(lp, cfn, parm);
  XrdAccAuthorize* acc = dynamic_cast<XrdAccAuthorize*>(authlib);

  if (acc == 0)
    TkEroute.Say("Failed to create AuthChangeFsUid object!");

  return acc;
}
