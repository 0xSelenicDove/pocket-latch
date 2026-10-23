using System;
using System.IO;
using System.Text;
using System.Management;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using System.Collections.Generic;

internal static class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern int GetCurrentPackageFamilyName(ref uint length, StringBuilder name);

    static object Read(RegistryKey machine, string path, string name)
    {
        using (var key = machine.OpenSubKey(path, false))
        {
            var value = key == null ? null : key.GetValue(name);
            if (value != null && !(value is int)) throw new InvalidDataException("Unexpected policy value type.");
            return value;
        }
    }

    static Dictionary<string, object> Collect()
    {
        var report = new Dictionary<string, object>();
        try
        {
            using (var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                report["policy"] = Read(machine, @"SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor", "AllowSecondaryAuthenticationDevice");
                report["mdmPolicy"] = Read(machine, @"SOFTWARE\Microsoft\PolicyManager\current\device\Authentication", "AllowSecondaryAuthenticationDevice");
                report["helloProtection"] = Read(machine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello", "Enabled");
            }
            report["policyRead"] = true;
        }
        catch (Exception error) { report["policyRead"] = false; report["policyError"] = error.Message; }
        try
        {
            using (var query = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\DeviceGuard", "SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard"))
            {
                query.Options.Timeout = TimeSpan.FromSeconds(8);
                using (var results = query.Get())
                    foreach (ManagementObject item in results)
                        using (item) { report["vbs"] = Convert.ToInt32(item["VirtualizationBasedSecurityStatus"]); break; }
            }
        }
        catch (Exception error) { report["vbsError"] = error.Message; }
        return report;
    }

    static int Main(string[] args)
    {
        try
        {
            if (Array.IndexOf(args, "--bluetooth") >= 0)
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "BluetoothHost", "BluetoothHost.exe")) { UseShellExecute = false });
                return 0;
            }
            if (args.Length == 1 && args[0] == "--check")
            {
                var check = Collect();
                return check.ContainsKey("policyRead") ? 0 : 1;
            }
            uint length = 0;
            GetCurrentPackageFamilyName(ref length, null);
            var family = new StringBuilder((int)length);
            if (GetCurrentPackageFamilyName(ref length, family) != 0) return 1;
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Packages", family.ToString(), "LocalState");
            var id = Guid.Parse(File.ReadAllText(Path.Combine(folder, "setup-request.txt"))).ToString();
            var report = Collect();
            report["request"] = id;
            var json = new JavaScriptSerializer().Serialize(report);
            File.WriteAllText(Path.Combine(folder, "setup-result.tmp"), json);
            File.Copy(Path.Combine(folder, "setup-result.tmp"), Path.Combine(folder, "setup-result.json"), true);
            return 0;
        }
        catch { return 1; }
    }
}
