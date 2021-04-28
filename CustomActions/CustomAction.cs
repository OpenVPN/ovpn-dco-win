using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Deployment.WindowsInstaller;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace CustomActions
{
    public class CustomActions
    {
        private static bool IsInstalling(InstallState current, InstallState requested)
        {
            return (InstallState.Local == requested || InstallState.Source == requested ||
                (InstallState.Default == requested && (InstallState.Local == current || InstallState.Source == current)));
        }

        private static bool IsReinstalling(InstallState current, InstallState requested)
        {
            return ((InstallState.Local == requested || InstallState.Source == requested || InstallState.Default == requested) &&
                (InstallState.Local == current || InstallState.Source == current));
        }

        private static bool IsUninstalling(InstallState current, InstallState requested)
        {
            return ((InstallState.Absent == requested || InstallState.Removed == requested) &&
                (InstallState.Local == current || InstallState.Source == current));
        }

        private static string CMP_OVPN_DCO_INF_GUID = "{4BE20469-2292-4AE2-B953-49AA0DA4165E}";
        private static string FILE_OVPN_DCO_INF = "ovpn-dco.inf";
        private static string DEFERRED_CA_NAME = "OvpnDcoProcess";
        private static string FILE_PNPUTIL_EXE = "pnputil.exe";
        private static int ERROR_SUCCESS_REBOOT_REQUIRED = 3010;
        private static int ERROR_ALREADY_UP_TO_DATE = 259;
        private static string ACTION_ADD_DRIVER = "AddDriver";
        private static string ACTION_DELETE_DRIVER = "DeleteDriver";
        private static string ACTION_NOOP = "Noop";
        private static string FILE_NEED_REBOOT = ".ovpn_dco_need_reboot";

        [CustomAction]
        public static ActionResult Evaluate(Session session)
        {
#if DEBUG
            MessageBox.Show("Attach debugger to rundll32", "CustomActions");
#endif

            // We're in immediate custom action, we should not change system state here
            // Instead figure out what to do in deferred CA

            string componentName = (string)session.Database.ExecuteScalar("SELECT `Component` FROM `Component` WHERE `ComponentId` = '{0}'", CMP_OVPN_DCO_INF_GUID);
            ComponentInfo component = session.Components[componentName];

            var tempPath = Path.GetTempPath();
            if (IsInstalling(component.CurrentState, component.RequestState) || IsReinstalling(component.CurrentState, component.RequestState))
            {
                // action|path-to-inf|path-to-user-temp (where we put file indicating if reboot is needed after (un)installation)
                session[DEFERRED_CA_NAME] = string.Format("{0}|{1}{2}|{3}", ACTION_ADD_DRIVER, session["OVPNDCO"], FILE_OVPN_DCO_INF, tempPath);
            }
            else if (IsUninstalling(component.CurrentState, component.RequestState))
            {
                session[DEFERRED_CA_NAME] = string.Format("{0}||{1}", ACTION_DELETE_DRIVER, tempPath);
            } else
            {
                session[DEFERRED_CA_NAME] = string.Format("{0}||", ACTION_NOOP);
            }

            return ActionResult.Success;
        }

        private static string GetPublishedName()
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = FILE_PNPUTIL_EXE,
                Arguments = "/enum-drivers",
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            var proc = System.Diagnostics.Process.Start(startInfo);
            string publishedName = "";
            while (!proc.StandardOutput.EndOfStream)
            {
                var kv = proc.StandardOutput.ReadLine().Split(':');
                if (kv[0].Trim() == "Published Name")
                    publishedName = kv[1].Trim();
                else if (kv[0].Trim() == "Original Name" && kv[1].Trim() == FILE_OVPN_DCO_INF)
                {
                    proc.StandardOutput.ReadToEnd();
                    break;
                }
                else
                    publishedName = "";
            }

            return publishedName;
        }

        private static ActionResult DeleteDriver(Session session, string tempPath)
        {
            try
            {
                var publishedName = GetPublishedName();
                if (publishedName.Length == 0)
                {
                    session.Log("Couldn't find Published Name for {0}, continue", FILE_OVPN_DCO_INF);
                    return ActionResult.Success;
                }

                session.Log("Remove {0} driver", publishedName);

                return RunPnpUtil(session, string.Format("/delete-driver \"{0}\" /uninstall", publishedName), tempPath);
            }
            catch (Exception e)
            {
                session.Log("Error deleting driver: {0}", e.ToString());
                // make sure uninstall continues if driver deletion failed
                return ActionResult.Success;
            }
        }

        private static ActionResult RunPnpUtil(Session session, string args, string tempPath)
        {
            var result = ActionResult.Success;

            var startInfo = new ProcessStartInfo
            {
                FileName = FILE_PNPUTIL_EXE,
                Arguments = args,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            session.Log("Executing {0} {1}", startInfo.FileName, startInfo.Arguments);

            string pathToRebootFile = Path.Combine(tempPath, FILE_NEED_REBOOT);
            File.Delete(pathToRebootFile);

            var proc = System.Diagnostics.Process.Start(startInfo);
            proc.WaitForExit();
            if (proc.ExitCode != 0)
            {
                if (proc.ExitCode == ERROR_SUCCESS_REBOOT_REQUIRED)
                {
                    session.Log("pnputil required reboot, create reboot indication file {0}", pathToRebootFile);

                    using (FileStream fs = File.Create(pathToRebootFile))
                    {
                        fs.WriteByte(0x65);
                    }
                }
                else if (proc.ExitCode == ERROR_ALREADY_UP_TO_DATE)
                {
                    session.Log("pnputil reported that driver is already up to date, continue");
                }
                else
                {
                    session.Log("Error executing pnputil: {0}", proc.ExitCode);
                    result = ActionResult.Failure;
                }
            }

            return result;
        }

        private static ActionResult AddDriver(Session session, string pathToInf, string tempPath)
        {
            return RunPnpUtil(session, string.Format("/add-driver \"{0}\" /install", pathToInf), tempPath);
        }

        [CustomAction]
        public static ActionResult Process(Session session)
        {
#if DEBUG
            MessageBox.Show("Attach debugger to rundll32", "CustomActions");
#endif

            string[] actions = session.CustomActionData.ToString().Split('|');

            string action = actions[0], pathToInf = actions[1], tempPath = actions[2];
            if (action == ACTION_ADD_DRIVER)
            {
                return AddDriver(session, pathToInf, tempPath);
            }
            else if (action == ACTION_DELETE_DRIVER)
            {
                return DeleteDriver(session, tempPath);
            }
            else if (action == ACTION_NOOP)
            {
                session.Log("Noop");
                return ActionResult.Success;
            } else
            {
                session.Log("Unknown action {0}", action);
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult CheckReboot(Session session)
        {
#if DEBUG
            MessageBox.Show("Attach debugger to rundll32", "CustomActions");
#endif

            string pathToRebootFile = Path.Combine(Path.GetTempPath(), FILE_NEED_REBOOT);
            if (File.Exists(pathToRebootFile))
            {
                File.Delete(pathToRebootFile);
                session.Log("Found reboot indication file {0}, schedule reboot", pathToRebootFile);
                session.SetMode(InstallRunMode.RebootAtEnd, true);
            }

            return ActionResult.Success;
        }
    }
}
