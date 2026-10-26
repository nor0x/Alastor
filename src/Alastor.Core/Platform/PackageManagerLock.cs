namespace Alastor.Core.Platform;

/// <summary>
/// One package transaction at a time within the agent: installing updates, upgrading or removing a package from the
/// dashboard. dpkg and rpm lock themselves too, but waiting here gives a clear order instead of a lock-timeout error.
/// </summary>
public static class PackageManagerLock
{
    public static readonly SemaphoreSlim Instance = new(1, 1);
}
