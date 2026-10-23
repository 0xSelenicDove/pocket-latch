namespace CdfProbe.Shared
{
    internal static class SetupChecks
    {
        internal static string PolicyText(uint? value) => value == 0
            ? "Blocked — companion sign-in is disabled by policy. Ask your administrator to enable Allow companion device for secondary authentication."
            : value == 1 ? "Configured to allow companion sign-in. Windows confirms effective eligibility during enrollment."
            : "Not configured — no explicit companion sign-in policy was found. Windows will confirm eligibility during enrollment.";

        internal static string ProtectionText(bool running) => running
            ? "Compatibility warning — VBS is running. Our protected-host test could not use companion sign-in. This is not proof that every protected PC is incompatible; security settings will not be changed."
            : "VBS is not running.";
    }
}
