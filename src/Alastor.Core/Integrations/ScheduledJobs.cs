using Alastor.Core.Contracts;
using Alastor.Core.Policy;

namespace Alastor.Core.Integrations;

/// <summary>
/// Optional capability: integrations with recurring work (update checks, CVE scans, audits). The supervisor runs each
/// job on its policy schedule (<see cref="ScheduledJob.ScheduleKey"/>), once right after it first appears, and on
/// demand from the dashboard ("Scan now"), off the heartbeat loop so a 10-minute scan never delays a heartbeat.
/// </summary>
public interface IScheduledJobProvider
{
    IReadOnlyList<ScheduledJob> Jobs { get; }
}

/// <param name="Id">Stable id, also the payload of the run-job command: <c>updates.check</c>, <c>updates.apply</c>, …</param>
/// <param name="ScheduleKey">The policy schedule path, e.g. <c>updates.checkSchedule</c> (see <see cref="ScheduleDefaults"/>).</param>
/// <param name="RunOnFirstStart">Run once as soon as the agent starts if it has never run, instead of waiting for the schedule.</param>
/// <param name="RunAsync">Does the work. <c>forced</c> is true for "now" requests from the dashboard. Never throws for expected failures: they go in the report.</param>
public sealed record ScheduledJob(
    string Id,
    string DisplayName,
    string ScheduleKey,
    bool RunOnFirstStart,
    Func<PolicyDocument, bool, CancellationToken, Task<AgentReport>> RunAsync);
